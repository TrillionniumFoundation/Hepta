"""Current-source controls for all 41 explicitly selected HIA instructions.

This file's first checkpoint is an unexecuted authoring draft. Qualification
requires the actual compiler image and all unchanged original callers.
"""
from __future__ import annotations
import ast
from contextlib import ExitStack
from functools import lru_cache
from hashlib import sha256
import inspect
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_machine_x64 as reference
from hepta.hia_machine_encoding_native import (
    SELECTOR as ENCODING_SELECTOR, COMMANDS, NativeEncodedCode,
    installed_machine_encoding)
from hepta.hia_machine_state_native import (
    SELECTOR as STATE_SELECTOR, MODES as STATE_MODES, installed_machine_state)
from hepta.hia_machine_instructions_native import (
    SOURCE, SELECTOR, MAGIC, MODES, MachineInstructionSession,
    installed_machine_instructions)
from tests import test_hia_machine_state_native as state_tests
from tests.test_hia_machine_encoding_native import cases, observe, observe_foreign_alu

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/fixtures/hia_machine_encoding_instructions_0d653c.py.txt'
FIXTURE_SHA256 = '17489158acb535e83ff14b68edd87327ca02dd7273bdbadf07ea271f9162b3bb'
DEVELOPMENT = 'HEPTA_HIA_MACHINE_INSTRUCTIONS_DEVELOPMENT_BUNDLE'
COLD = 'HEPTA_HIA_MACHINE_INSTRUCTIONS_COLD_REPORT'
EVIDENCE = 'HEPTA_HIA_MACHINE_INSTRUCTIONS_FIXTURE_EVIDENCE'
SELECTORS = (ENCODING_SELECTOR, STATE_SELECTOR, SELECTOR)

def foreign_observation(factory, name):
    code = factory()
    events = []
    error = None
    try:
        if name in ('pair-order', 'imul-order', 'setcc-repeated-register'):
            class Mapping:
                def get(self, key, default):
                    events.append(['register', key, default])
                    if name == 'setcc-repeated-register':
                        return 'r10' if len(events) == 1 else 'r11'
                    return key
            code.scratch_registers = Mapping()
            if name == 'pair-order':
                code.mov_rr('r10', 'r11')
            elif name == 'imul-order':
                code.imul('r10', 'r11')
            else:
                code.setcc('ne', 'r10')
        elif name == 'align-emit-binding':
            def old_emit(raw):
                events.append(['original-emit', raw.hex()])
            def new_emit(raw):
                events.append(['replacement-emit', raw.hex()])
            class Data:
                def __len__(self):
                    events.append(['length'])
                    code.emit = new_emit
                    return 3
            code.emit, code.data = old_emit, Data()
            code.align(16)
        elif name in ('shift-foreign-true', 'shift-foreign-false'):
            class Truth:
                def __bool__(self):
                    events.append(['truth'])
                    return name.endswith('true')
            class Count:
                def __eq__(self, other):
                    events.append(['equality', other])
                    return Truth()
            code.shift('shr', 'r9', Count())
        elif name == 'move-option-binding':
            class Truth:
                def __bool__(self):
                    events.append(['truth'])
                    def emit(raw):
                        events.append(['replacement-emit', raw.hex()])
                    code.emit = emit
                    return True
            class Option:
                def __eq__(self, other):
                    events.append(['equality', other])
                    return Truth()
            code.move_immediate = Option()
            code.mov_imm('r10', 17)
        elif name in ('branch-append-binding', 'call-append-binding'):
            armed = [False]
            class Append:
                def __init__(self, label):
                    self.label = label
                @property
                def append(self):
                    events.append(['bind-append', self.label])
                    armed[0] = True
                    def append(value):
                        events.append(['append', self.label, value])
                    return append
            class Data(bytearray):
                def __len__(self):
                    if armed[0]:
                        events.append(['length-after-append-bind'])
                        armed[0] = False
                        if name == 'branch-append-binding':
                            code.fixups = Append('replacement')
                        else:
                            code.relocations = Append('replacement')
                    return super().__len__()
            code.data = Data()
            if name == 'branch-append-binding':
                code.fixups = Append('original')
                code.jmp('destination')
            else:
                code.relocations = Append('original')
                code.call('external')
        elif name == 'virtual-aliases':
            def shift(*args):
                events.append(['shift', list(args)])
                return 'foreign-return-is-ignored'
            def imul(*args):
                events.append(['imul', list(args)])
                return 'foreign-return-is-ignored'
            code.shift, code.imul = shift, imul
            results = [code.shift_imm('sar', 'r10', 2), code.shift_cl('shl', 'r11'),
                       code.shl('r12', 3), code.shr('r13', 'cl'), code.sar('r14', 4),
                       code.imul_rr('r10', 'r11')]
            events.append(['returns', results])
        else:
            raise AssertionError('unknown foreign observation')
    except BaseException as exc:
        error = state_tests.exception(exc)
    return {'events': events, 'error': error,
            'data': bytes(code.data).hex() if isinstance(code.data, (bytes, bytearray)) else None}


class MachineInstructionsSourceTests(unittest.TestCase):
    def test_generated_source_and_original_compiler_limits(self):
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        from tools.generate_hia_machine_instructions import document
        value = document()
        self.assertEqual(render_assembly(value).encode(), SOURCE.read_bytes())
        self.assertEqual(assemble_program(SOURCE.read_text()).as_dict(), value)
        self.assertLessEqual(len(SOURCE.read_bytes()), 1 << 20)
        self.assertLessEqual(len(SOURCE.read_text().splitlines()), 16384)
        self.assertLessEqual(len(value['functions']), 128)
        self.assertLessEqual(sum(len(f['blocks']) for f in value['functions']), 1536)
        self.assertLessEqual(sum(len(b['ops']) for f in value['functions'] for b in f['blocks']), 8192)
        for function in value['functions']:
            self.assertLessEqual(len(function['blocks']), 256)
            values = list(function['params'])
            for block in function['blocks']:
                self.assertLessEqual(len(block['params']), 16)
                values.extend(block['params'])
                for operation in block['ops']:
                    values.extend(operation['out'])
            self.assertLessEqual(len({v['name'] for v in values}), 2048)
        self.assertEqual(len(MODES), 41)

    def test_complete_original_classes_and_fixture_bytes_are_retained(self):
        self.assertEqual(sha256(FIXTURE.read_bytes()).hexdigest(), FIXTURE_SHA256)
        def class_node(raw, name, ignored=()):
            value = next(n for n in ast.parse(raw).body if isinstance(n, ast.ClassDef) and n.name == name)
            value.body = [n for n in value.body if not isinstance(n, ast.FunctionDef) or n.name not in ignored]
            return ast.dump(value, include_attributes=False)
        self.assertEqual(class_node(FIXTURE.read_text(), 'NativeEncodedCode'),
                         class_node(inspect.getsource(sys.modules[NativeEncodedCode.__module__]), 'NativeEncodedCode'))
        self.assertEqual(sha256(state_tests.FIXTURE.read_bytes()).hexdigest(), state_tests.FIXTURE_SHA256)
        self.assertEqual(class_node(state_tests.FIXTURE.read_text(), 'Code', ('__new__',)),
                         class_node(inspect.getsource(reference), 'Code', ('__new__',)))

    def test_cold_admission_refuses_before_output(self):
        from tools.build_hia_machine_instructions import build
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            compiler, cold = root / 'compiler', root / 'cold.json'
            compiler.write_bytes(b'not a compiler')
            cold.write_text('{}')
            output = root / 'must-not-exist'
            with self.assertRaisesRegex(ValueError, 'completed matching native cold'):
                build(output, compiler, cold)
            self.assertFalse(output.exists())

    def test_unselected_and_subclasses_preserve_existing_owner(self):
        with patch.dict(os.environ, dict.fromkeys(SELECTORS, '')):
            self.assertEqual(type(reference.Code()), reference.Code)
            self.assertEqual(reference.native_implementation_identity(), b'')
        with patch.dict(os.environ, dict.fromkeys(SELECTORS, '') | {SELECTOR: '/missing/instructions'}):
            with self.assertRaisesRegex(reference.MachineEncodingError, 'requires native Code state'):
                reference.Code()
            class OwnCode(reference.Code):
                pass
            self.assertEqual(type(OwnCode()), OwnCode)


class MachineInstructionsNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        development, cold = os.environ.get(DEVELOPMENT), os.environ.get(COLD)
        if development and cold:
            raise AssertionError('development bundle cannot override requested cold report')
        evidence = os.environ.get(EVIDENCE)
        if evidence:
            cls.folder = Path(evidence).resolve()
            cls.folder.mkdir(parents=True, exist_ok=False)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-machine-instructions-')
            cls.addClassCleanup(cls.temporary.cleanup)
            cls.folder = Path(cls.temporary.name)
        if cold:
            from tools.build_hia_machine_instructions import build
            from tools.build_hia_machine_state import build as build_state
            from tools.build_hia_machine_encoding import build as build_encoding
            outer = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(outer['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
            cls.manifest = build(cls.folder / 'instructions', compiler, Path(cold))
            cls.state_manifest = build_state(cls.folder / 'state', compiler, Path(cold))
            cls.encoding_manifest = build_encoding(cls.folder / 'encoding', compiler, Path(cold))
            cls.scope = 'MATCHING_SOURCE_COLD_BUILD'
        elif development:
            bundle = json.loads(Path(development).read_bytes())
            cls.manifest = Path(bundle['instructions_manifest']).resolve(strict=True)
            cls.state_manifest = Path(bundle['state_manifest']).resolve(strict=True)
            cls.encoding_manifest = Path(bundle['encoding_manifest']).resolve(strict=True)
            cls.scope = 'EXPLICIT_DEVELOPMENT_ONLY'
        else:
            raise unittest.SkipTest('requires explicit matching cold or development bundle')
        cls.native = installed_machine_instructions(str(cls.manifest))
        cls.state = installed_machine_state(str(cls.state_manifest))
        cls.encoding = installed_machine_encoding(str(cls.encoding_manifest))

    def selected(self):
        stack = ExitStack()
        stack.enter_context(patch.dict(os.environ, {
            SELECTOR: str(self.manifest), STATE_SELECTOR: str(self.state_manifest),
            ENCODING_SELECTOR: str(self.encoding_manifest)}))
        def forbidden(*args, **kwargs):
            raise AssertionError('retained Code state, instruction or operand owner entered')
        for name, member in reference.Code.__dict__.items():
            if inspect.isfunction(member) and name != '__new__':
                stack.enter_context(patch.object(reference.Code, name, forbidden))
        stack.enter_context(patch.object(reference.Code, 'offset', property(forbidden)))
        for name in ('_reg', '_condition', '_disp32'):
            if hasattr(reference, name):
                stack.enter_context(patch.object(reference, name, forbidden))
        for name, member in NativeEncodedCode.__dict__.items():
            if inspect.isfunction(member) and name != '_bytes':
                stack.enter_context(patch.object(NativeEncodedCode, name, forbidden))
        return stack

    def save(self, name, value):
        (self.folder / name).write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')

    def test_all_original_instruction_cases_with_every_old_instruction_owner_forbidden(self):
        rows = cases()
        self.assertEqual(len(rows), 159)
        expected = [observe(state_tests.oracle().Code, row) for row in rows]
        self.native.calls.clear()
        self.state.calls.clear()
        self.encoding.calls.clear()
        observations = []
        with self.selected():
            for row, wanted in zip(rows, expected):
                with self.subTest(case=row['id']):
                    actual = observe(reference.Code, row)
                    observations.append({'id': row['id'], 'expected': wanted, 'actual': actual})
                    self.assertEqual(actual, wanted)
            self.assertEqual(reference.Code().offset, 0)
        self.assertEqual(set(self.native.calls), set(MODES))
        self.assertEqual(set(self.state.calls), set(STATE_MODES))
        self.assertEqual(set(self.encoding.calls), set(COMMANDS))
        self.save('original-instruction-observations.json', observations)

    def test_foreign_operand_truth_method_binding_and_append_order(self):
        names = ('pair-order', 'imul-order', 'setcc-repeated-register',
                 'align-emit-binding', 'shift-foreign-true', 'shift-foreign-false',
                 'move-option-binding', 'branch-append-binding',
                 'call-append-binding', 'virtual-aliases')
        rows = []
        expected = [foreign_observation(state_tests.oracle().Code, name) for name in names]
        with self.selected():
            for name, wanted in zip(names, expected):
                with self.subTest(case=name):
                    actual = foreign_observation(reference.Code, name)
                    rows.append({'id': name, 'expected': wanted, 'actual': actual})
                    self.assertEqual(actual, wanted)
        combinations = [([False, False, False], 7, False),
                        ([False, True, False], 7, False),
                        ([False, False, True], 7, False),
                        ([False, True, False], 128, False),
                        ([False, False, False], 7, True)]
        expected = [observe_foreign_alu(state_tests.oracle().Code, *row) for row in combinations]
        with self.selected():
            for number, (row, wanted) in enumerate(zip(combinations, expected)):
                with self.subTest(foreign_alu=row):
                    actual = observe_foreign_alu(reference.Code, *row)
                    rows.append({'id': 'foreign-alu-' + str(number), 'expected': wanted, 'actual': actual})
                    self.assertEqual(actual, wanted)
        self.save('foreign-instruction-observations.json', rows)

    def test_original_word_displacement_condition_symbol_and_refusal_priority(self):
        rows = []
        def add(name, operation, arguments, **options):
            rows.append({'id': name, 'operations': [(operation, arguments)], 'options': options})
        for compact in ('movabs', 'mov32_if_exact'):
            for value in (-(1 << 96) - (1 << 63), -(1 << 63) - 1, -(1 << 63), -1,
                          0, (1 << 32) - 1, 1 << 32, (1 << 64) - 1, 1 << 64, 1 << 128):
                add('word-' + compact + '-' + str(value), 'mov_imm', ['r10', value], move_immediate=compact)
        for value in (-(1 << 96) - (1 << 31), -(1 << 31) - 1, -(1 << 31), -1,
                      0, (1 << 31) - 1, 1 << 31, 1 << 96):
            add('disp-' + str(value), 'load', ['r10', 'r11', value])
            add('imm-' + str(value), 'alu_imm', ['xor', 'r10', value])
        for condition in reference._CONDITIONS:
            add('condition-' + condition, 'setcc', [condition, 'r10'])
        for symbol in ('a', '_', 'A0_', 'a' * 192, 'a' * 193, '', '0name', 'a\n', 'a\0', 'aé', 'é'):
            add('symbol-' + repr(symbol), 'call', [symbol])
        for number, (operation, arguments) in enumerate((
                ('alu_imm', ['bad', 'bad', True]), ('alu_imm', ['add', 'bad', True]),
                ('shift', ['bad', 'bad', True]), ('shift', ['shl', 'bad', True]),
                ('mov_imm', ['bad', True]), ('load', ['bad', 'bad', True]),
                ('cmov', ['bad', 'bad', 'bad']), ('setcc', ['bad', 'bad']),
                ('jcc', ['bad', '']), ('jcc', ['e', '']), ('jmp', ['a' * 513]))):
            add('priority-' + str(number), operation, arguments)
        expected = [observe(state_tests.oracle().Code, row) for row in rows]
        observations = []
        with self.selected():
            for row, wanted in zip(rows, expected):
                with self.subTest(case=row['id']):
                    actual = observe(reference.Code, row)
                    observations.append({'id': row['id'], 'expected': wanted, 'actual': actual})
                    self.assertEqual(actual, wanted)
        self.save('operand-boundary-observations.json', observations)

    def test_actual_64MiB_and_original_mutable_state_boundaries(self):
        state_tests.MachineStateNativeTests.test_actual_64MiB_and_signed_rel32_boundaries(self)
        state_tests.MachineStateNativeTests.test_foreign_metaclass_membership_uses_no_hash_and_keeps_original_truth_order(self)

    def test_backend_identity_and_three_selectors_are_pinned_across_emit(self):
        from hepta import hia_program_native as backend
        from hepta.hia_program import verify_program
        from tests.test_hia_machine_plan import call_document
        checked = verify_program(call_document())
        with patch.dict(os.environ, dict.fromkeys(SELECTORS, '')):
            original = backend.emit_program_machine(checked)
        with self.selected():
            current = backend.emit_program_machine(checked)
        self.assertEqual(current.object_bytes, original.object_bytes)
        self.assertNotEqual(current.implementation_sha256, original.implementation_sha256)
        old_render = backend._Emitter.render
        def changing_render(emitter):
            for selector in SELECTORS:
                os.environ[selector] = '/missing/changed-after-pin'
            return old_render(emitter)
        with self.selected(), patch.object(backend._Emitter, 'render', changing_render):
            repeated = backend.emit_program_machine(checked)
        self.assertEqual(repeated.object_bytes, current.object_bytes)
        self.assertEqual(repeated.implementation_sha256, current.implementation_sha256)
        with self.selected():
            state_tests.assert_primitive_bridge_identity_bound(self, backend, (
                'hia_machine_state_native.py', 'hia_machine_instructions_native.py', 'hia_json_wire_native.py', 'hia_machine_transport.py'))
            from hepta import hia_machine_encoding_native as encoding_bridge
            from hepta import hia_machine_state_native as state_bridge
            from hepta import hia_machine_instructions_native as instruction_bridge
            self.save('source-admission-window.json', state_tests.assert_scope_source_admission_bound(
                self, backend, checked, (encoding_bridge, state_bridge, instruction_bridge)))

    def test_malformed_ack_and_failed_append_cannot_be_replayed(self):
        code = state_tests.oracle().Code()
        code._bytes = lambda *args, **values: b'\xe9'
        session = MachineInstructionSession(self.native, code, 39, 'target')
        self.assertEqual(session.step(), 1)
        before = bytes(session.workspace)
        bad = struct.pack('<10Q', MAGIC, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        self.assertEqual(session.step(bad), 0xfffffffd)
        self.assertEqual(bytes(session.workspace), before)
        with self.assertRaisesRegex(RuntimeError, 'no unconsumed'):
            session.observe()
        events = []
        class FailingAppend:
            def append(self, value):
                events.append(value)
                raise OSError('original append changed before raising')
        code.fixups = FailingAppend()
        session = MachineInstructionSession(self.native, code, 39, 'target')
        status = session.step()
        with self.assertRaisesRegex(OSError, 'original append changed before raising'):
            while status == 1:
                session.observe()
                status = session.step()
        self.assertEqual(events, [(1, 'target')])
        for action in (session.observe, session.step):
            with self.assertRaises(RuntimeError):
                action()
        self.assertEqual(events, [(1, 'target')])
        self.assertEqual(code.data, b'\xe9')
        state_tests.assert_terminal_after_native_bookkeeping_error(
            self, self.native, lambda: MachineInstructionSession(self.native, state_tests.oracle().Code(), 39, 'x'))

    def test_warm_image_rechecks_package_source(self):
        from hepta import hia_machine_instructions_native as bridge
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / 'machine_instructions.hepta'
            source.write_bytes(SOURCE.read_bytes())
            with patch.object(bridge, 'SOURCE', source):
                self.assertIs(installed_machine_instructions(str(self.manifest)), self.native)
                source.write_bytes(source.read_bytes() + b'\n')
                with self.assertRaisesRegex(ValueError, 'source identity mismatch'):
                    installed_machine_instructions(str(self.manifest))
                source.unlink()
                with self.assertRaises(FileNotFoundError):
                    installed_machine_instructions(str(self.manifest))

    def test_actual_installed_wheel_uses_three_HIA_owners_without_authoring(self):
        from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, PUBLICATION_BUILD_FILES, SOURCE_BUILD_FILES, COMPILER_BUILD_FILES, BACKEND_BUILD_FILES, EMITTER_BUILD_FILES, BYTE_WRAPPER_BUILD_FILES, MACHINE_OBJECT_BUILD_FILES, EXECUTION_OBSERVATION_BUILD_FILES, CONTINUATION_BUILD_FILES, ENTRY_BUILD_FILES
        case = self.folder / 'installed-control'
        case.mkdir()
        source = case / 'source'
        source.mkdir()
        shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        resources = (tuple('docs/' + name for name in DISCOVERY_FILES) + NATIVE_SOURCE_FILES + PUBLICATION_BUILD_FILES + SOURCE_BUILD_FILES + COMPILER_BUILD_FILES) + BACKEND_BUILD_FILES + EMITTER_BUILD_FILES + BYTE_WRAPPER_BUILD_FILES + MACHINE_OBJECT_BUILD_FILES + EXECUTION_OBSERVATION_BUILD_FILES + CONTINUATION_BUILD_FILES + ENTRY_BUILD_FILES
        for name in (*resources, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        packaging_python = os.environ.get('HEPTA_HIA_TEST_PACKAGING_PYTHON', sys.executable)
        wheels, installed = case / 'wheels', case / 'installed'
        records = []
        def command(arguments, label, *, env=None):
            result = subprocess.run(arguments, cwd=case, env=env, capture_output=True, timeout=120)
            (case / (label + '.stdout')).write_bytes(result.stdout)
            (case / (label + '.stderr')).write_bytes(result.stderr)
            records.append({'argv': arguments, 'returncode': result.returncode,
                            'stdout_sha256': sha256(result.stdout).hexdigest(),
                            'stderr_sha256': sha256(result.stderr).hexdigest()})
            (case / 'processes.json').write_text(json.dumps(records, sort_keys=True, indent=2) + '\n')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return result
        command([packaging_python, '-B', '-m', 'pip', 'wheel', '--no-cache-dir', '--no-deps',
                 '--no-index', '--no-build-isolation', '--wheel-dir', str(wheels), str(source)], 'wheel-build')
        wheel, = wheels.glob('*.whl')
        command([packaging_python, '-B', '-m', 'pip', 'install', '--no-cache-dir', '--no-deps',
                 '--no-index', '--target', str(installed), str(wheel)], 'wheel-install')
        child = '''import importlib.abc,inspect,json,os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
class NoTools(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname=='tools' or fullname.startswith('tools.'):
            raise AssertionError('installed instructions imported authoring tools')
sys.meta_path.insert(0,NoTools())
from hepta import hia_machine_x64 as m
from hepta.hia_machine_encoding_native import NativeEncodedCode
from hepta.hia_machine_state_native import installed_machine_state
from hepta.hia_machine_instructions_native import SOURCE,installed_machine_instructions
assert Path(sys.argv[1]) in SOURCE.parents
def forbidden(*a,**k):raise AssertionError('retained state or instruction entered')
for cls in (m.Code,NativeEncodedCode):
    for name,member in tuple(cls.__dict__.items()):
        if inspect.isfunction(member) and name not in {'__new__','_bytes'}:setattr(cls,name,forbidden)
m.Code.offset=property(forbidden)
for name in ('_reg','_condition','_disp32'):
    if hasattr(m,name):setattr(m,name,forbidden)
for name,path in zip(('HEPTA_HIA_MACHINE_ENCODING_MANIFEST','HEPTA_HIA_MACHINE_STATE_MANIFEST','HEPTA_HIA_MACHINE_INSTRUCTIONS_MANIFEST'),sys.argv[2:5]):
    os.environ[name]=path
c=m.Code(scratch_registers={'r10':'r11','r11':'r10'})
c.label('a');c.jmp('z');c.mov_imm('r10',42);c.label('z');c.ret()
assert c.offset==16
raw,relocations=c.finalize()
assert raw.hex()=='e90a00000049bb2a00000000000000c3'
assert relocations==[] and c.finalize()[0]==raw
c.data[0]=0x90
assert c.finalize()[0][0]==0x90
owner=installed_machine_instructions(sys.argv[4])
state=installed_machine_state(sys.argv[3])
assert all(owner.calls[k]>0 for k in ('jmp','mov_imm','ret'))
assert all(state.calls[k]>0 for k in ('initialize','emit','label','offset','register','finalize'))
print(json.dumps({'status':'INSTALLED_NATIVE_MACHINE_INSTRUCTIONS_PASS',
 'native_instructions':dict(owner.calls),'native_state':dict(state.calls),
 'source':str(SOURCE),'image_sha256':owner.image_sha256,
 'isolated_without_site':bool(sys.flags.isolated and sys.flags.no_site),
 'empty_PATH':os.environ['PATH']=='','authoring_forbidden':True,'retained_owners_forbidden':True}))
'''
        script = case / 'installed-control.py'
        script.write_text(child)
        env = {k: v for k, v in os.environ.items() if not k.startswith('HEPTA_HIA_')}
        env.update(PATH='', PYTHONPATH='')
        result = command([sys.executable, '-I', '-S', '-B', str(script), str(installed),
                          str(self.encoding_manifest), str(self.state_manifest), str(self.manifest)],
                         'installed-execution', env=env)
        report = json.loads(result.stdout)
        self.assertEqual(report['status'], 'INSTALLED_NATIVE_MACHINE_INSTRUCTIONS_PASS')
        self.assertTrue(report['isolated_without_site'])
        self.save('installed-control-report.json', report)


if __name__ == '__main__':
    unittest.main()
