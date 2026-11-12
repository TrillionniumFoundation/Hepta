"""Real HIA controls for shared CALL transfer and value-context short circuit."""
from __future__ import annotations

import ast
import ctypes
from hashlib import sha256
import inspect
import json
import os
from pathlib import Path
import struct
import tempfile
import textwrap
import unittest
from unittest.mock import patch

from hepta import hia_machine_plan_control_native as transport
from tests import hia_machine_frame_shared_fixtures as fixtures

ROOT = Path(__file__).resolve().parents[1]
COLD = 'HEPTA_HIA_CORE_LOWERING_COLD_REPORT'
DEVELOPMENT = 'HEPTA_HIA_MACHINE_FRAME_DEVELOPMENT_COMPILER'
EVIDENCE = 'HEPTA_HIA_MACHINE_FRAME_EVIDENCE'


def mechanism_document():
    from tools import generate_hia_machine_plan_control as generator
    from tools.hia_machine_plan_control import compile_policy
    policy = compile_policy(Path(fixtures.__file__).read_text())
    with patch.object(generator, 'program', return_value=policy):
        return generator.document()


class SharedFrameSourceTests(unittest.TestCase):
    def test_every_original_Call_has_unique_temporary_operands_and_a_fixed_keyword_template(self):
        from tools import generate_hia_machine_plan_control as plan
        from tools import generate_hia_core_lowering as core
        from tools.hia_machine_plan_control import OPS
        tree = ast.parse(textwrap.dedent(inspect.getsource(transport.PlanFrame._call)))
        template_shapes = set()
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Call)
                    and isinstance(node.func.func, ast.Attribute)
                    and node.func.func.attr == '_move_call_operand'):
                self.assertFalse(any(isinstance(arg, ast.Starred) for arg in node.args))
                self.assertTrue(all(keyword.arg is not None for keyword in node.keywords))
                template_shapes.add((len(node.args), tuple(k.arg for k in node.keywords)))
        counts = []
        for generator in (plan, core):
            policy = generator.program()
            count = 0
            for function in policy.functions:
                for instruction in function.instructions:
                    if instruction['kind'] != 'effect' or instruction['opcode'] != OPS['CALL']:
                        continue
                    count += 1
                    arguments = instruction['arguments']
                    slots = [argument.slot for argument in arguments]
                    self.assertEqual(len(slots), len(set(slots)))
                    self.assertEqual(instruction['consume'], arguments)
                    for argument in arguments:
                        self.assertTrue(argument.temporary)
                        self.assertIn(argument.slot, function.temporary_slots)
                        self.assertNotIn(argument.slot, function.cell_slots)
                    positional, keywords, *names = instruction['raw']
                    self.assertEqual(len(arguments), 1 + positional + keywords)
                    self.assertEqual(len(names), keywords)
                    shape = positional, tuple(policy.literals[index] for index in names)
                    self.assertIn(shape, template_shapes)
            counts.append(count)
        self.assertEqual(counts, [100, 409])

    def test_mechanism_is_complete_verified_HIA_with_the_original_compiler_limits(self):
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        raw = render_assembly(mechanism_document()).encode()
        document = assemble_program(raw).as_dict()
        functions = document['functions']
        blocks = [block for function in functions for block in function['blocks']]
        self.assertLessEqual(len(raw), 1 << 20)
        self.assertLessEqual(len(raw.splitlines()), 16384)
        self.assertLessEqual(len(functions), 128)
        self.assertLessEqual(len(blocks), 1536)
        self.assertLessEqual(sum(len(block['ops']) + 1 for block in blocks), 8192)
        for function in functions:
            self.assertLessEqual(len(function['params']), 16)
            self.assertLessEqual(len(function['blocks']), 256)
            definitions = {value['name'] for value in function['params']}
            for block in function['blocks']:
                definitions.update(value['name'] for value in block['params'])
                for operation in block['ops']:
                    definitions.update(value['name'] for value in operation['out'])
                    self.assertLessEqual(len(operation.get('args', ())), 16)
            self.assertLessEqual(len(definitions), 2048)


class SharedFrameNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cold, development = os.environ.get(COLD), os.environ.get(DEVELOPMENT)
        if cold and development:
            raise AssertionError('development compiler cannot override requested matching cold')
        if cold:
            from tools.build_hia_json_preflight import admit_cold_build
            report = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(report['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
            admit_cold_build(compiler.read_bytes(), Path(cold).read_bytes())
            cls.scope = 'MATCHING_SOURCE_COLD_MECHANISM_CONTROL'
        elif development:
            compiler = Path(development).resolve(strict=True)
            cls.scope = 'EXPLICIT_DEVELOPMENT_ONLY'
        else:
            raise unittest.SkipTest('requires matching Core cold report or explicit development compiler')
        compiler_before = compiler.read_bytes()
        evidence = os.environ.get(EVIDENCE)
        if evidence:
            cls.folder = Path(evidence).resolve()
            cls.folder.mkdir(parents=True, exist_ok=False)
        else:
            temporary = tempfile.TemporaryDirectory(prefix='hia-shared-frame-')
            cls.addClassCleanup(temporary.cleanup)
            cls.folder = Path(temporary.name)
        from hepta.hia_agent_assembly import render_assembly
        from tools.qualify_hia_selfhost import compile_stage
        raw = render_assembly(mechanism_document()).encode()
        cls.hia = cls.folder / 'mechanism.hiaasm'
        cls.hia.write_bytes(raw)
        image, receipt = compile_stage(cls.folder, 'mechanism', compiler, raw)
        if compiler.read_bytes() != compiler_before or cls.hia.read_bytes() != raw:
            raise AssertionError('shared mechanism compile input changed')
        cls.image = image.read_bytes()
        cls.image_sha = sha256(cls.image).hexdigest()
        (cls.folder / 'fixture.json').write_text(json.dumps({
            'scope': cls.scope, 'source_sha256': sha256(raw).hexdigest(),
            'image_sha256': cls.image_sha,
            'compiler_sha256': sha256(compiler_before).hexdigest(),
            'receipt': receipt, 'whole_native': False}, indent=2) + '\n')

    def new_owner(self):
        return transport.NativeMachinePlanControl(self.image, self.image_sha)

    def test_original_120_lifetime_identity_error_and_short_circuit_observations(self):
        owner = self.new_owner()
        rows = fixtures.run_cases(owner, fixtures)
        self.assertEqual(len(rows), 120)
        self.assertEqual(len({(row['case'], row['outer']) for row in rows}), 120)
        (self.folder / 'original-120-observations.json').write_text(json.dumps({
            'runtime_profile': owner.runtime_profile, 'entries': owner.entries,
            'rows': rows}, indent=2) + '\n')
        self.assertGreater(owner.entries, 0)
        for row in rows:
            with self.subTest(case=row['case'], outer=row['outer']):
                self.assertFalse(any(row['original']['final_alive'].values()))
                self.assertEqual(row['native'], row['original'])

    def test_complete_native_frames_and_all_buffer_bytes_equal_independent_Core_VM(self):
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        program = assemble_program(self.hia.read_bytes())
        function = program.as_dict()['functions'][0]
        owner = self.new_owner()
        native_entry = owner._entry
        rows = []

        def entry(source, source_size, output, output_size, workspace, workspace_size):
            before = [ctypes.string_at(pointer, size) for pointer, size in
                      ((source, source_size), (output, output_size), (workspace, workspace_size))]
            guards = [ctypes.create_string_buffer(b'Z' * 16 + raw + b'Y' * 16, len(raw) + 32)
                      for raw in before]
            actual = native_entry(ctypes.addressof(guards[0]) + 16, source_size,
                                  ctypes.addressof(guards[1]) + 16, output_size,
                                  ctypes.addressof(guards[2]) + 16, workspace_size)
            memory = [_Owner(-1-index, bytearray(raw)) for index, raw in enumerate(before)]
            vm = _Machine(program, 12_000_000, 64 << 20, None, 128)
            expected = vm.invoke(function, [_View(memory[0], False), _View(memory[1], True),
                                           _View(memory[2], True)])[0]
            self.assertEqual(actual, expected)
            self.assertEqual(bytes(memory[0].data), before[0])
            for guard, physical in zip(guards, memory):
                self.assertEqual(guard.raw[:16], b'Z' * 16)
                self.assertEqual(guard.raw[-16:], b'Y' * 16)
                self.assertEqual(guard.raw[16:-16], bytes(physical.data))
            ctypes.memmove(output, guards[1].raw[16:-16], output_size)
            ctypes.memmove(workspace, guards[2].raw[16:-16], workspace_size)
            rows.append({'command': struct.unpack_from('<Q', before[2])[0], 'return': actual,
                         'source_bytes': source_size, 'output_bytes': output_size,
                         'workspace_bytes': workspace_size,
                         'output_sha256': sha256(guards[1].raw[16:-16]).hexdigest(),
                         'workspace_sha256': sha256(guards[2].raw[16:-16]).hexdigest()})
            return actual

        owner._entry = entry
        owner._initialize_control()
        for mode, name, context in (
                (1, 'validate_plan', fixtures.BoolContext(True, None)),
                (2, 'register_assignment_witness', fixtures.BoolContext(False, None)),
                (1, 'validate_plan', fixtures.BoolContext(False, None)),
                (2, 'register_assignment_witness', fixtures.BoolContext(True, None)),
                (5, '_require', fixtures.CallContext(2, False, False)),
                (6, '_permutation', fixtures.CallContext(3, True, True))):
            actual = fixtures.with_ambient(lambda value: owner.run(mode, value), context, True)
            self.assertFalse(any(actual['final_alive'].values()))
        self.assertTrue(any(row['command'] == 2 for row in rows))
        self.assertTrue(any(row['command'] == 4 for row in rows))
        self.assertIn(3, [row['return'] for row in rows])
        (self.folder / 'all-native-VM-frames.json').write_text(json.dumps(rows, indent=2) + '\n')

    def test_claimed_Call_moves_slots_once_and_lost_real_ack_cannot_repeat_effect(self):
        owner = self.new_owner()
        observations = []
        for lose_ack in (False, True):
            context = fixtures.CallContext(1, False, False)
            frame = owner.prepare(5, (context,))
            while True:
                self.assertEqual(frame.step(), 1)
                opcode, _, arguments, _, _ = frame._parts()
                if opcode == 9 and isinstance(frame._get(arguments[0]), fixtures.Callable):
                    break
                frame.service(frame.pending)
            issued = frame.pending
            frame.service(issued)
            self.assertTrue(frame.executed and frame.completed)
            self.assertTrue(all(frame.values[slot] is transport._EMPTY for slot in arguments))
            self.assertEqual(sum(event[0] == 'call' for event in context.trace), 1)
            with self.assertRaises(RuntimeError):
                frame.service(issued)
            if lose_ack:
                original = frame._invoke
                failure = KeyboardInterrupt('after the actual CALL acknowledgement')
                returns = []

                def interrupted(command, *args, **kwargs):
                    result = original(command, *args, **kwargs)
                    if command == 1:
                        returns.append(result)
                        raise failure
                    return result

                frame._invoke = interrupted
                with self.assertRaises(KeyboardInterrupt) as caught:
                    frame.step()
                self.assertIs(caught.exception, failure)
                self.assertEqual(len(returns), 1)
                self.assertTrue(frame.closed and frame._uncertain)
                for replay in (frame.step, frame.take, lambda: frame.service(issued)):
                    with self.assertRaises(RuntimeError):
                        replay()
                frame.close()
                self.assertIs(transport._UNCONFIRMED_RETIREMENTS[frame.nonce], frame)
            else:
                while frame.step() == 1:
                    frame.service(frame.pending)
                self.assertEqual(frame.take(), 41)
                frame.close()
            self.assertEqual(sum(event[0] == 'call' for event in context.trace), 1)
            observations.append({'lose_ack': lose_ack, 'nonce': frame.nonce,
                                 'trace': context.trace, 'unknown': frame._uncertain})
        (self.folder / 'claim-move-and-ack.json').write_text(json.dumps(observations, indent=2) + '\n')
