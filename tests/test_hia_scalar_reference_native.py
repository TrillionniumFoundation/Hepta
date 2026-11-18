"""Independent checks for the selected reference VM scalar semantics."""

from hashlib import sha256
from itertools import product
import json
import os
from pathlib import Path
import random
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_program import WIDTHS, integer_range, verify_program
from hepta.hia_program_runtime import HIAProgramTrap, _Machine, execute_program
from hepta.hia_scalar_reference_native import (
    OPCODES, OWNER_RECORD_BYTES, SCHEMA, SELECTOR, SOURCE, NativeScalarReference,
)


class ScalarReferenceSourceTests(unittest.TestCase):
    def test_checked_in_hia_source_reproduces(self):
        from tools.generate_hia_scalar_reference import document

        source = SOURCE.read_text()
        self.assertEqual(source, render_assembly(document()))
        assemble_program(source)

    def test_symbolic_recipe_hia_source_reproduces(self):
        from hepta.hia_scalar_symbolic_native import SOURCE as SYMBOLIC_SOURCE
        from tools.generate_hia_scalar_symbolic import document

        source = SYMBOLIC_SOURCE.read_text()
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
        cls.compiler = compiler
        cls.image = image
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

    def test_standalone_reference_preserves_scalar_wire_and_grows_call_space(self):
        from hepta.hia_program import verify_program
        from hepta.hia_scalar_reference_wire import PROGRAM_MAGIC, PROGRAM_RESULT, program_wire
        from tests.test_hia_program import b, f, i, m, ret
        from tools.generate_hia_native_filter import (
            REFERENCE_CLI_ADAPTER, REFERENCE_CLI_MAGIC, REFERENCE_CLI_PACKER, elf_header, reference_cli_document,
        )
        from tools.build_hia_agent_batch_commit import adapter_layout
        from tools.qualify_hia_selfhost import compile_stage
        from tools.qualify_hia_selfhost_cli import inspect_executable

        source = SOURCE.parents[2] / REFERENCE_CLI_PACKER
        self.assertEqual(source.read_text(), render_assembly(reference_cli_document()))
        directory = self.compiler.parent / 'scalar-standalone'
        directory.mkdir()
        packer, _ = compile_stage(directory, 'packer', self.compiler, source.read_bytes())
        image = self.image.read_bytes()
        executable, _ = compile_stage(directory, 'executor', packer,
            struct.pack('<2Q', REFERENCE_CLI_MAGIC, len(image)) + image, output_extension='.elf')
        inspected = inspect_executable(executable.read_bytes())
        self.assertEqual(inspected['elf_type'], 'ET_EXEC')
        adapter = SOURCE.parents[2] / REFERENCE_CLI_ADAPTER
        stub, holes, _ = adapter_layout(directory, REFERENCE_CLI_ADAPTER, adapter.read_bytes(),
                                        {'reference': 'reference_call_hole'})
        hole = holes['reference'] + len(elf_header())
        packed = executable.read_bytes()
        self.assertEqual(packed[len(elf_header()):hole], stub[:holes['reference']])
        self.assertEqual(packed[hole+4:len(elf_header()) + len(stub)], stub[holes['reference']+4:])
        self.assertEqual(packed[len(elf_header()) + len(stub):], image)
        executable.chmod(0o500)

        argument = [('x', 'i32')]
        identity = m(f('identity', argument, ['i32'], [], [b('entry', argument, [], ret('x'))]))
        recursive = m(f('again', argument, ['i32'], [], [b('entry', argument, [
            i('call', ['x'], [('y', 'i32')], function='again')], ret('y'))]))

        def frame(program, name, *, depth=256, steps=2000, override_registers=None):
            raw = verify_program(program).canonical_bytes
            body, registers, bounce, returns, sites = program_wire(raw, name)
            self.assertFalse(sites)
            header = struct.pack('<8Q', PROGRAM_MAGIC, steps, depth,
                                 override_registers or registers, bounce, len(body), 1, len(returns))
            return header + body[64:] + struct.pack('<q', -132)

        def run(value, *arguments):
            return subprocess.run([executable, *arguments], input=value, capture_output=True,
                                  env={'PATH': ''}, timeout=10)

        returned = run(frame(identity, 'identity'))
        self.assertEqual((returned.returncode, returned.stderr), (0, b''))
        self.assertEqual(struct.unpack('<4Qq', returned.stdout), (PROGRAM_RESULT, 0, 2, 0, -132))
        # Twenty-five simultaneous frames exceed the initial workspace even though the
        # input program and all referenced register numbers remain small.
        limited = run(frame(recursive, 'again', depth=25, override_registers=150_000))
        self.assertEqual((limited.returncode, limited.stderr), (0, b''))
        self.assertEqual(struct.unpack('<4Q', limited.stdout)[:3], (PROGRAM_RESULT, 6, 50))
        steps = run(frame(recursive, 'again', depth=10, steps=9, override_registers=150_000))
        self.assertEqual((steps.returncode, steps.stderr), (0, b''))
        self.assertEqual(struct.unpack('<4Q', steps.stdout)[:3], (PROGRAM_RESULT, 5, 10))
        low_memory = subprocess.run(['/usr/bin/prlimit', '--as=50331648:50331648', '--', executable],
                                    input=frame(recursive, 'again', depth=25, override_registers=150_000),
                                    capture_output=True, env={'PATH': ''}, timeout=10)
        self.assertEqual((low_memory.returncode, low_memory.stderr), (0, b''))
        result_magic, status, ticks, detail = struct.unpack('<4Q', low_memory.stdout)
        self.assertEqual((result_magic, status, detail), (PROGRAM_RESULT, 12, 0))
        self.assertGreater(ticks, 4)
        self.assertLess(ticks, 50)

        from hepta.hia_agent_runner import run_reference_batch
        checked = verify_program(identity)
        cases = [{'function': 'identity', 'arguments': [value]} for value in (-132, 0, 319)]
        budget = {'timeout_ms': 15000, 'memory_bytes': 128 << 20}
        expected = run_reference_batch(checked, cases, **budget)
        binary = executable.read_bytes()
        pin = sha256(binary).hexdigest()
        with (patch.dict(os.environ, {SELECTOR: str(self.manifest)}),
              patch('hepta.hia_native_helpers.pinned_reference_executable', return_value=(binary, pin))):
            selected = run_reference_batch(checked, cases, **budget)
        self.assertEqual(selected['status'], 'returned', selected)
        self.assertEqual(selected['report']['observations'], expected['report']['observations'])
        self.assertEqual(selected['report']['reference_executable_sha256'], pin)
        self.assertEqual(selected['report']['reference_standalone_calls'], len(cases))
        for raw, options, code in ((b'bad', (), 2), (b'X' * (72), (), 2),
                                  (b'', ('not-an-option',), 64), (bytes((32 << 20) + 1), (), 3)):
            response = run(raw, *options)
            self.assertEqual((response.returncode, response.stdout, response.stderr), (code, b'', b''))

    def test_standalone_owned_reference_preserves_grown_state_chains_and_returned_loans(self):
        from hepta.hia_agent_runner import run_reference_batch
        from hepta.hia_program_runtime import HIAProgramBudgetExceeded, _ReferenceResources
        from hepta.hia_scalar_reference_native import child_owned_reference, sealed_reference_bytes
        from tests.test_hia_program import b, c, f, i, m, resource_program, ret
        from tests.test_hia_returned_chain_loans import chain_program
        from tests.test_hia_returned_loans import loan_program
        from tools.build_hia_owned_reference_cli import assemble
        from tools.generate_hia_owned_reference import ADAPTER_PATH, PACKER_PATH, SOURCE_PATH, cli_document, document

        root = SOURCE.parents[2]
        sources = {path: (root / path).read_bytes() for path in (ADAPTER_PATH, PACKER_PATH, SOURCE_PATH)}
        self.assertEqual(sources[SOURCE_PATH], render_assembly(document()).encode())
        self.assertEqual(sources[PACKER_PATH], render_assembly(cli_document()).encode())
        directory = self.compiler.parent / 'owned-standalone'
        directory.mkdir()
        binary, report = assemble(directory, self.compiler, sources)
        self.assertEqual(report['executable']['elf_type'], 'ET_EXEC')
        digest = sha256(binary).hexdigest()
        operations = [c('size', 'usize', 100_000), i('buffer.new', ['size'], [('owner', 'buffer')])]
        loans = [f'loan{n}' for n in range(80)]
        operations.extend(i('borrow.read', ['owner'], [(name, 'readbuf')]) for name in loans)
        operations.extend(i('loan.end', [name]) for name in reversed(loans))
        operations.append(i('owner.drop', ['owner']))
        wide = m(f('wide', [], [], ['alloc', 'trap'], [b('entry', [], operations, ret())]))
        chain, loans = chain_program('mut', 'child'), loan_program('read', 'recursive')
        inputs = [(wide, 'wide', [], {}), (wide, 'wide', [], {'max_steps': 154}),
                  (chain, chain['exports'][0], [73], {}), (chain, chain['exports'][0], [73], {'max_steps': 31}),
                  (loans, loans['exports'][0], [20, 211], {}),
                  (resource_program(), 'owned', [10, 255], {'allocation_fail_at': 1}),
                  (resource_program(), 'owned', [10, 255], {'max_heap_bytes': 7}),
                  (resource_program(), 'owned', [0, 255], {})]

        def observations():
            rows = []
            for program, entry, arguments, limits in inputs:
                try:
                    rows.append(execute_program(program, entry, arguments, **limits))
                except (HIAProgramBudgetExceeded, HIAProgramTrap) as error:
                    rows.append(error.report)
            return rows

        expected = observations()
        self.assertEqual(expected[0]['resources']['loans_ended'], 80)
        self.assertEqual(expected[0]['resources']['peak_bytes'], 100_000)
        with (patch.dict(os.environ, {SELECTOR: str(self.manifest)}),
              sealed_reference_bytes(binary) as fd,
              child_owned_reference({'fd': os.dup(fd), 'sha256': digest}) as selected,
              patch.object(_ReferenceResources, '__init__', side_effect=AssertionError('host resource adapter'))):
            self.assertEqual(observations(), expected)
            self.assertEqual(selected.calls, len(inputs))

        cases = [{'function': 'owned', 'arguments': [length, 171]} for length in (1, 100_000, 0)]
        program = verify_program(resource_program())
        limits = {'timeout_ms': 15000, 'memory_bytes': 64 << 20}
        baseline = run_reference_batch(program, cases, **limits)
        with (patch.dict(os.environ, {SELECTOR: str(self.manifest)}),
              patch('hepta.hia_native_helpers.pinned_owned_reference_executable', return_value=(binary, digest))):
            actual = run_reference_batch(program, cases, **limits)
        self.assertEqual(actual['status'], 'returned', actual)
        self.assertEqual(actual['report']['observations'], baseline['report']['observations'])
        self.assertEqual(actual['report']['owned_reference_executable_sha256'], digest)
        self.assertEqual(actual['report']['owned_reference_standalone_calls'], len(cases))

    def test_symbolic_recipes_preserve_solver_operations_and_actual_checker_routes(self):
        import z3

        from hepta.hia_optimization import _Encoder as OptimizationEncoder, verify_optimization
        from hepta.hia_scalar_symbolic_native import (
            MAX_BLOCKS, MAX_EDGES, MAX_OPERATIONS, MAX_PARAMETERS, MAX_RETURNS,
            NativeScalarSymbolic, PROFILE_REFUSALS, SCHEMA, SELECTOR, SOURCE, SymbolicRecipeRejected,
        )
        from hepta import hia_translation_validation
        from hepta.hia_translation_validation import _Encoder as TranslationEncoder, validate_translation
        from tests.test_hia_translation_validation import arithmetic
        from tools.qualify_hia_selfhost import compile_stage

        image, _ = compile_stage(self.compiler.parent, 'symbolic', self.compiler, SOURCE.read_bytes())
        raw = image.read_bytes()
        native = NativeScalarSymbolic(raw, sha256(raw).hexdigest())
        manifest = image.with_name('symbolic-manifest.json')
        manifest.write_text(json.dumps({'schema': SCHEMA, 'source_sha256': sha256(SOURCE.read_bytes()).hexdigest(),
            'image_path': image.name, 'image_sha256': native.image_sha256,
            'compiler_sha256': sha256(self.compiler.read_bytes()).hexdigest()}))

        graph_names = ['a', 'b', 'c', 'd']
        self.assertEqual(native.function_order(graph_names, [('d', 'd'), ('c',), (), ()],
            MAX_OPERATIONS, MAX_PARAMETERS, MAX_RETURNS, 0), (('a', 'b', 'd', 'c'), None))
        self.assertEqual(native.function_order(graph_names, [('b',), ('a',), (), ()],
            0, 0, 0, 0), ((), PROFILE_REFUSALS[-1]))
        for expected, facts in enumerate(((MAX_OPERATIONS + 1, MAX_PARAMETERS + 1, 0, 7),
                (0, MAX_PARAMETERS + 1, 0, 7), (0, 0, 0, 7), (0, 0, 0, 6), (0, 0, 0, 4))):
            self.assertEqual(native.function_order(graph_names, [()] * 4, *facts),
                             ((), PROFILE_REFUSALS[expected]))
        self.assertEqual(native.function_order([str(i) for i in range(MAX_BLOCKS + 1)], (),
            0, 0, 0, 0), ((), PROFILE_REFUSALS[0]))

        shapes = []
        for kind in WIDTHS:
            for opcode in OPCODES:
                if opcode.startswith(('bool.', 'cast.')) or opcode == 'select':
                    continue
                arity = 1 if opcode.endswith('.not') or opcode == 'int.neg.checked' else 2
                result = 'bool' if opcode.startswith('compare.') else kind
                shapes.append((opcode, {}, [kind] * arity, result))
            for result in WIDTHS:
                for mode in ('wrap', 'checked'):
                    shapes.append(('int.cast', {'mode': mode}, [kind], result))
            lo, hi = integer_range(kind)
            for literal in (lo, hi, 0):
                shapes.append(('const', {'value': literal}, [], kind))
        for opcode in ('bool.and', 'bool.or', 'compare.eq', 'compare.ne', 'bool.not'):
            shapes.append((opcode, {}, ['bool'] * (1 if opcode == 'bool.not' else 2), 'bool'))
        for kind in ('bool', 'unit', *WIDTHS):
            shapes.append(('select', {}, ['bool', kind, kind], kind))
        shapes.extend(('const', {'value': value}, [], kind)
                      for kind, value in (('unit', None), ('bool', True), ('bool', False)))
        context = z3.Context()

        def equivalent(first, second):
            if first is None or second is None:
                self.assertIs(first, second)
                return
            if not z3.eq(first, second):
                proof = z3.Solver(ctx=first.ctx)
                proof.set(timeout=3000)
                proof.add(first != second)
                self.assertEqual(proof.check(), z3.unsat)

        for edge_count in (0, 1, 2, 11, MAX_EDGES):
            guards = tuple(z3.Bool(f'edge_{n}', context) for n in range(edge_count))
            values = tuple(z3.BitVecVal(n + 1, 16, context) for n in range(edge_count))
            default = z3.BitVecVal(0, 16, context)
            expected_join = z3.Or(*guards) if guards else z3.BoolVal(False, context)
            self.assertTrue(z3.eq(native.control(z3, context, 'join', guards, edges=edge_count)[0],
                                  expected_join))
            expected_phi = values[0] if edge_count == 1 else default
            if edge_count != 1:
                for guard, value in zip(guards, values):
                    expected_phi = z3.If(guard, value, expected_phi)
            self.assertTrue(z3.eq(native.control(z3, context, 'phi',
                (*guards, *values, default), edges=edge_count)[0], expected_phi))
        with self.assertRaises(SymbolicRecipeRejected):
            native.control(z3, context, 'join', (), edges=MAX_EDGES + 1)
        reach, test = z3.Bools('reachable predicate', ctx=context)
        hit, missed = native.control(z3, context, 'split', (reach, test))
        self.assertTrue(z3.eq(hit, z3.And(reach, test)))
        self.assertTrue(z3.eq(missed, z3.And(reach, z3.Not(test))))
        final = native.control(z3, context, 'observe', (reach, 4, z3.IntVal(-1, context)))[0]
        self.assertTrue(z3.eq(final, z3.If(reach, 4, z3.IntVal(-1, context))))

        trans = TranslationEncoder(z3)
        for opcode, attrs, inputs, output in shapes:
            with self.subTest(opcode=opcode, inputs=inputs, output=output, attrs=attrs):
                names = ['a', 'b', 'c'][:len(inputs)]
                op = {'op': opcode, 'attrs': attrs, 'args': names,
                      'out': [{'name': 'v', 'type': output}]}
                original = OptimizationEncoder(z3,
                    {name: (z3.Bool(name, context) if kind == 'bool' else
                            z3.BitVec(name, WIDTHS.get(kind, 8), context), kind)
                     for name, kind in zip(names, inputs)}, context)
                selected = OptimizationEncoder(z3, original.env, context)
                selected.native_symbolic = native
                original.operation(op)
                selected.operation(op)
                equivalent(original.env['v'][0], selected.env['v'][0])
                equivalent(original.trap, selected.trap)
                symbolic = {name: trans.input(index, kind)
                            for index, (name, kind) in enumerate(zip(names, inputs))}
                types = dict(zip(names, inputs))
                reference, expected = trans.operation(op, symbolic, types)
                trans.native_symbolic = native
                try:
                    actual, traps = trans.operation(op, symbolic, types)
                finally:
                    trans.native_symbolic = None
                equivalent(reference, actual)
                self.assertEqual([code for code, _ in traps], [code for code, _ in expected])
                for (_, first), (_, second) in zip(expected, traps):
                    equivalent(first, second)

        original = arithmetic('int.add.wrap')
        changed = arithmetic('int.sub.wrap')
        with (patch.dict(os.environ, {SELECTOR: str(manifest)}),
              patch.object(OptimizationEncoder, '_reference_operation', side_effect=AssertionError('host symbolic opcode')),
              patch.object(TranslationEncoder, '_reference_operation', side_effect=AssertionError('host symbolic opcode')),
              patch.object(TranslationEncoder, '_reference_any', side_effect=AssertionError('host guard merge')),
              patch.object(TranslationEncoder, 'choose', side_effect=AssertionError('host phi selection')),
              patch.object(hia_translation_validation, '_reference_profile', side_effect=AssertionError('host CFG profile'))):
            optimized = verify_optimization(original, original)
            self.assertEqual(optimized['status'], 'verified', optimized)
            self.assertEqual(verify_optimization(original, changed)['status'], 'rejected')
            translated = validate_translation(original, original)
            self.assertEqual(translated['status'], 'proved', translated)
            self.assertEqual(validate_translation(original, changed)['status'], 'disproved')
            from tests.test_hia_translation_validation import ScalarTranslationProofTests
            comparison = ScalarTranslationProofTests()
            comparison.test_cfg_phi_and_select_have_identical_all_input_behavior()
            comparison.test_branch_guard_masks_unexecuted_overflow()
            comparison.test_first_trap_code_and_operation_order_are_observable()

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
              patch.object(_Machine, 'allocate', side_effect=AssertionError('host allocator policy')),
              patch.object(_Machine, 'new_owner', side_effect=AssertionError('host owner issuance')),
              patch.object(_Machine, 'drop', side_effect=AssertionError('host owner accounting'))):
            self.assertEqual(compare(), expected)

    def test_resource_wire_rejects_malformed_command_before_releasing_operands(self):
        import ctypes

        from hepta.hia_scalar_reference_wire import (
            PROGRAM_RESULT, RESOURCE, RESOURCE_CODES, RESOURCE_PROGRAM_MAGIC, program_wire, resource_request,
        )
        from tests.test_hia_program import resource_program

        checked = verify_program(resource_program())
        body, registers, bounce, returns, uses_resources = program_wire(
            checked.canonical_bytes, 'owned', allow_resources=True)
        self.assertTrue(uses_resources)
        header = struct.pack('<8Q', RESOURCE_PROGRAM_MAGIC, 100, 9, registers, bounce,
                             len(body), 2, len(returns))
        wire = header + body[64:] + struct.pack('<2Q', 8, 27)

        def observe(packet):
            source = ctypes.create_string_buffer(packet)
            output = ctypes.create_string_buffer(32 + 8 * bounce)
            state = ctypes.create_string_buffer(64 + (registers + bounce + 1) * 8)
            size = self.native._entry(source, len(packet), output, len(output), state, len(state))
            return size, output.raw

        size, out = observe(wire)
        self.assertEqual(size, 40)
        identity, status, steps, descriptor, operand = struct.unpack_from('<5Q', out)
        self.assertEqual((identity, status, operand), (PROGRAM_RESULT, 13, 8))
        request = resource_request(wire, descriptor)
        self.assertIn(request.operation, ('buffer.new', 'buffer.try_new'))
        self.assertEqual(request.inputs, 1)
        self.assertIsNone(request.first_kind)
        self.assertGreater(steps, 0)

        start = struct.unpack_from('<Q', wire, 64)[0]
        site = start
        while struct.unpack_from('<Q', wire, site)[0] != RESOURCE:
            site += 64
        self.assertEqual(struct.unpack_from('<Q', wire, site + 8)[0], descriptor)
        malformed = ((descriptor, len(RESOURCE_CODES) + 2), (descriptor + 8, 4),
                     (descriptor + 16, 0), (descriptor + 24, request.outputs + 1),
                     (site + 8, descriptor + 1), (site + 8, len(body) - 16))
        for position, replacement in malformed:
            altered = bytearray(wire)
            struct.pack_into('<Q', altered, position, replacement)
            size, output = observe(bytes(altered))
            self.assertEqual((size, output), (0xffffffff, bytes(len(output))))

    def test_native_owner_arena_reuses_slots_rejects_stale_ids_and_accounts_limits(self):
        table = bytearray(OWNER_RECORD_BYTES * 2)

        def ask(operation, subject=0, fail_at=0):
            return self.native.owner_operation(table, operation, subject, 8, fail_at)

        self.assertEqual(ask(1, 8, fail_at=1)[:2], (0, 3))
        self.assertEqual(ask(1, 8)[:2], (0, 4))
        self.assertEqual(self.native.attach_storage(table, None, 8, 8), (2, 8))
        storage = bytearray(b'abcdefgh')
        status, handle = self.native.attach_storage(table, storage, 8, 8)
        self.assertEqual(status, 0)
        self.assertEqual(storage, bytes(8))
        self.assertEqual(ask(3, handle)[:2], (0, 8))
        self.assertEqual(ask(1, 1)[:2], (0, 2))
        frozen = table[:]
        self.assertEqual(ask(2, 0)[0], 3)
        self.assertEqual(table, frozen)
        self.assertEqual(ask(4, handle)[:2], (0, 8))
        status, replacement, _ = ask(2)
        self.assertEqual(status, 0)
        self.assertNotEqual(handle, replacement)
        self.assertEqual(ask(4, handle)[0], 1)
        self.assertEqual(ask(0)[2], [2, 1, 1, 2, 1, 0, 8])
        self.assertEqual(ask(4, replacement)[:2], (0, 0))
        self.assertEqual(ask(0)[2], [2, 1, 1, 2, 2, 0, 8])

    def test_owned_storage_operations_do_not_export_host_slices(self):
        from hepta.hia_program_runtime import _ReferenceResources

        table = bytearray(OWNER_RECORD_BYTES * 4)
        backing = bytearray(19)
        first = self.native.attach_storage(table, backing, 8, 19)[1]
        second = self.native.attach_storage(table, backing, 8, 19)[1]

        def access(operation, owner, **fields):
            return self.native.storage_bytes(operation, table, backing, owner, **fields)

        access('store', first, offset=0, value=7)
        access('fill', first, offset=1, count=4, value=17)
        access('copy_range', second, source=first, offset=2, source_offset=0, count=5)
        access('move', second, offset=1, source_offset=2, count=5)
        access('swap', second, offset=1, source_offset=5)
        self.assertEqual(backing[8:16], bytes((0, 17, 17, 17, 17, 7, 17, 0)))
        self.assertEqual(access('load', second, offset=5), 7)
        prior = backing[:]
        with self.assertRaises(HIAProgramTrap):
            access('copy', second, source=first, count=9)
        self.native.owner_operation(table, 4, first, 19)
        with self.assertRaises(RuntimeError):
            access('copy_range', second, source=first, count=1)
        with self.assertRaises(RuntimeError):
            access('copy_range', second, source=second, count=1)
        self.assertEqual(backing, prior)

        from tests.test_hia_program import resource_program

        program = resource_program()
        baseline = execute_program(program, 'owned', [8, 25])
        with (patch.dict(os.environ, {SELECTOR: str(self.manifest)}),
              patch.object(_ReferenceResources, 'byte_storage', side_effect=AssertionError('host slice')),
              patch.object(NativeScalarReference, 'byte_operation', side_effect=AssertionError('old byte transport'))):
            actual = execute_program(program, 'owned', [8, 25])
        self.assertEqual(actual, baseline)

    def test_native_storage_compacts_live_spans_and_zeros_reclaimed_bytes(self):
        import mmap

        maximum = 19
        table = bytearray(OWNER_RECORD_BYTES * 5)
        with mmap.mmap(-1, maximum) as region:
            def allocate(amount):
                status, handle = self.native.attach_storage(table, region, amount, maximum)
                self.assertEqual(status, 0)
                return handle

            def inspect(handle):
                status, extent, (offset, *_) = self.native.owner_operation(table, 3, handle, maximum)
                self.assertEqual(status, 0)
                return offset, extent

            first, kept, last = (allocate(amount) for amount in (4, 6, 4))
            region[:14] = b'abcd012345WXYZ'
            self.native.owner_operation(table, 4, first, maximum)
            self.assertEqual(inspect(kept), (4, 6))
            inserted = allocate(8)  # Required live extent 18, but the remaining tail is only five.
            self.assertEqual(inspect(kept), (0, 6))
            self.assertEqual(inspect(last), (6, 4))
            self.assertEqual(inspect(inserted), (10, 8))
            self.assertEqual(region[:18], b'012345WXYZ' + bytes(8))
            self.assertNotEqual(first, inserted)
            self.assertEqual(self.native.owner_operation(table, 3, first, maximum)[0], 1)

            region[10:18] = b'released'
            self.native.owner_operation(table, 4, inserted, maximum)
            replacement = allocate(9)
            self.assertEqual(inspect(replacement), (10, 9))
            self.assertEqual(region[:19], b'012345WXYZ' + bytes(9))

        from tests.test_hia_program import b, c, f, i, m, ret

        ops = [c('four', 'usize', 4), c('six', 'usize', 6), c('eight', 'usize', 8),
               c('zero', 'usize', 0), c('mark', 'u8', 253),
               i('buffer.new', ['four'], [('first', 'buffer')]),
               i('buffer.new', ['six'], [('keep', 'buffer')]),
               i('buffer.new', ['four'], [('last', 'buffer')]),
               i('borrow.mut', ['keep'], [('write', 'mutbuf')]),
               i('buffer.store', ['write', 'zero', 'mark']), i('loan.end', ['write']),
               i('owner.drop', ['first']),
               i('buffer.new', ['eight'], [('insert', 'buffer')]),
               i('borrow.read', ['keep'], [('read', 'readbuf')]),
               i('buffer.load', ['read', 'zero'], [('kept', 'u8')]), i('loan.end', ['read']),
               i('borrow.read', ['insert'], [('read_new', 'readbuf')]),
               i('buffer.load', ['read_new', 'zero'], [('created', 'u8')]), i('loan.end', ['read_new']),
               *(i('owner.drop', [name]) for name in ('keep', 'last', 'insert'))]
        program = m(f('compact', [], ['u8', 'u8'], ['alloc', 'read', 'write', 'trap'],
                      [b('entry', [], ops, ret('kept', 'created'))]))
        baseline = execute_program(program, 'compact', (), max_heap_bytes=maximum)
        self.assertEqual(baseline['values'], [253, 0])
        with (patch.dict(os.environ, {SELECTOR: str(self.manifest)}),
              patch.object(_Machine, 'new_owner', side_effect=AssertionError('host owner object')),
              patch.object(_Machine, 'operation', side_effect=AssertionError('host instruction dispatch'))):
            actual = execute_program(program, 'compact', (), max_heap_bytes=maximum)
        self.assertEqual(actual, baseline)

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
              patch.object(_Machine, 'allocate', side_effect=AssertionError('host allocator policy')),
              patch.object(_Machine, 'new_owner', side_effect=AssertionError('host owner issuance')),
              patch.object(_Machine, 'drop', side_effect=AssertionError('host owner accounting'))):
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
