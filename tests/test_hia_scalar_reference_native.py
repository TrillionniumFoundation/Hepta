"""Independent checks for the selected reference VM scalar semantics."""

from hashlib import sha256
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
