"""Original mutable-object observations for explicitly selected HIA Code state."""
from __future__ import annotations

import ast
from contextlib import ExitStack
import ctypes
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
import types
import unittest
from unittest.mock import patch

from hepta import hia_machine_x64 as reference
from hepta.hia_machine_encoding_native import SELECTOR as ENCODING_SELECTOR, NativeEncodedCode
from hepta.hia_machine_state_native import (
    SOURCE, SELECTOR, MAGIC, MachineStateSession, installed_machine_state)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/fixtures/hia_machine_x64_state_608.py.txt'
FIXTURE_SHA256 = '83e3072c3a6cd806a66a0c2bcd206a92725040434d83877871bcd201533bf3ec'
DEVELOPMENT = 'HEPTA_HIA_MACHINE_STATE_DEVELOPMENT_BUNDLE'
COLD = 'HEPTA_HIA_MACHINE_STATE_COLD_REPORT'
EVIDENCE = 'HEPTA_HIA_MACHINE_STATE_FIXTURE_EVIDENCE'


@lru_cache(maxsize=1)
def oracle():
    raw = FIXTURE.read_bytes()
    if sha256(raw).hexdigest() != FIXTURE_SHA256:
        raise AssertionError('original complete Code fixture changed')
    module = types.ModuleType('hepta._machine_state_reference_fixture')
    module.__package__ = 'hepta'
    module.__file__ = str(FIXTURE)
    exec(compile(raw, str(FIXTURE), 'exec'), module.__dict__)
    module._NATIVE_OWNER.set(None)
    return module


def exception(exc):
    return {'type': type(exc).__name__, 'message': str(exc)}


def mutable_observation(factory, case):
    events = []
    code = factory()
    result = {'exception': None}
    try:
        if case == 'label-rebind':
            class Labels(dict):
                def __contains__(self, name):
                    events.append(['contains', name])
                    code.labels = NewLabels()
                    return False
            class NewLabels(dict):
                def __setitem__(self, key, value):
                    events.append(['set', key, value])
                    super().__setitem__(key, value)
            class Data:
                def __len__(self):
                    events.append(['data-length'])
                    return 9
            code.labels, code.data = Labels(), Data()
            code.label('target')
            result['labels'] = dict(code.labels)
        elif case == 'emit-rebind':
            class Before:
                def __len__(self):
                    events.append(['data-length'])
                    code.data = After()
                    return 2
            class After:
                @property
                def extend(self):
                    events.append(['bind-extend'])
                    def extend(raw):
                        events.append(['extend', raw.hex()])
                    return extend
            code.data = Before()
            code.emit(b'abc')
        elif case == 'double-offset-and-row-copy':
            class Offset:
                def __add__(self, value):
                    events.append(['offset-add', value])
                    return 4
                def __index__(self):
                    events.append(['offset-index'])
                    return 0
            class Position:
                def __sub__(self, value):
                    events.append(['position-sub', value])
                    return 16
            class Labels:
                def __contains__(self, key):
                    events.append(['contains', key])
                    return True
                def __getitem__(self, key):
                    events.append(['get-label', key])
                    return Position()
            class Row:
                def keys(self):
                    events.append(['row-keys'])
                    return ['offset', 'symbol']
                def __getitem__(self, key):
                    events.append(['row-get', key])
                    return 1 if key == 'offset' else 'external'
            code.data = bytearray(4)
            code.labels = Labels()
            code.fixups = [(Offset(), 'target')]
            code.relocations = [Row()]
            raw, rows = code.finalize()
            result.update(bytes=raw.hex(), rows=rows, original_data=code.data.hex())
        elif case == 'labels-rebound-between-contains-and-get':
            class Before:
                def __contains__(self, key):
                    events.append(['contains', key])
                    code.labels = After()
                    return True
            class After:
                def __getitem__(self, key):
                    events.append(['get', key])
                    return 8
            code.data = bytearray(4)
            code.labels = Before()
            code.fixups = [(0, 'target')]
            raw, rows = code.finalize()
            result.update(bytes=raw.hex(), rows=rows, original_data=code.data.hex())
        elif case == 'relocation-live-iteration':
            class Row:
                def keys(self):
                    events.append(['row-keys'])
                    code.relocations.append({'second': 2})
                    return ['first']
                def __getitem__(self, key):
                    events.append(['row-get', key])
                    return 1
            code.relocations = [Row()]
            raw, rows = code.finalize()
            result.update(bytes=raw.hex(), rows=rows)
        elif case == 'register-map-binding':
            class Mapping:
                @property
                def get(self):
                    events.append(['bind-get'])
                    def get(value, default):
                        events.append(['get', value, default])
                        return 'r15'
                    return get
            code.scratch_registers = Mapping()
            result['register'] = code._reg('r10')
        elif case == 'non-string-missing-label':
            code.data = bytearray(4)
            code.fixups = [(0, 17)]
            code.finalize()
        elif case == 'invalid-fixup-shape':
            code.fixups = [(0, 'a', 'extra')]
            code.finalize()
        elif case == 'invalid-offset-arithmetic':
            code.labels = {'x': 9}
            code.fixups = [('bad', 'x')]
            code.finalize()
        else:
            raise AssertionError('unknown observation case')
    except BaseException as exc:
        result['exception'] = exception(exc)
    result['events'] = events
    return result



def assert_terminal_after_native_bookkeeping_error(test, owner, make_session):
    """Execute the real native entry, then fault only diagnostic accounting."""
    original_entry = owner._entry
    for failure in (KeyboardInterrupt, MemoryError):
        entries = []
        def actual_entry(*arguments):
            entries.append(1)
            return original_entry(*arguments)
        class FailingCounter:
            def __getitem__(self, key):
                return 0
            def __setitem__(self, key, value):
                raise failure('injected after actual native transition')
        with patch.object(owner, '_entry', actual_entry), patch.object(owner, 'transitions', FailingCounter()):
            session = make_session()
            with test.assertRaisesRegex(failure, 'injected after actual native transition'):
                session.step()
            test.assertEqual(entries, [1])
            test.assertTrue(session.finished)
            test.assertFalse(session.pending)
            test.assertFalse(session.prepared)
            workspace = bytes(session.workspace)
            for action in (session.step, session.observe, lambda: session.step(session.packet)):
                with test.assertRaises(RuntimeError):
                    action()
            test.assertEqual(entries, [1])
            test.assertEqual(bytes(session.workspace), workspace)


def assert_primitive_bridge_identity_bound(test, backend, names):
    """Each actual bridge dependency must contribute its bytes to the key."""
    expected = backend._implementation_hash()
    original_read = Path.read_bytes
    package = Path(reference.__file__).parent
    for name in names:
        target = package / name
        def changed_read(path):
            raw = original_read(path)
            return raw + b'\n# identity observation only\n' if path == target else raw
        with patch.object(Path, 'read_bytes', changed_read):
            test.assertNotEqual(backend._implementation_hash(), expected, name)


def assert_scope_source_admission_bound(test, backend, checked, bridges):
    """Drift after actual owner selection must refuse before the first key."""
    original_entry = backend._emit_program_machine_with_encoding
    observations = []
    for bridge in bridges:
        raw = bridge.SOURCE.read_bytes()
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / bridge.SOURCE.name
            source.write_bytes(raw)
            entered = []
            def drift_before_first_identity(*arguments, **keywords):
                entered.append(1)
                source.write_bytes(raw + b'\n')
                return original_entry(*arguments, **keywords)
            with patch.object(bridge, 'SOURCE', source), \
                    patch.object(backend, '_emit_program_machine_with_encoding',
                                 drift_before_first_identity), \
                    patch.object(backend._Emitter, 'render',
                                 side_effect=AssertionError('source drift reached emission')) as render:
                with test.assertRaisesRegex(ValueError, 'source identity mismatch') as caught:
                    backend.emit_program_machine(checked)
                render.assert_not_called()
                test.assertEqual(entered, [1])
                observations.append({
                    'owner': bridge.__name__,
                    'admitted_source_sha256': sha256(raw).hexdigest(),
                    'changed_source_sha256': sha256(source.read_bytes()).hexdigest(),
                    'ordinary_emit_entries': len(entered),
                    'emitter_entries': render.call_count,
                    'refusal': str(caught.exception),
                })
    return observations

class MachineStateSourceTests(unittest.TestCase):
    def test_generated_source_and_original_compiler_limits(self):
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        from tools.generate_hia_machine_state import document
        document_value = document()
        self.assertEqual(render_assembly(document_value).encode(), SOURCE.read_bytes())
        self.assertEqual(assemble_program(SOURCE.read_text()).as_dict(), document_value)
        self.assertLessEqual(len(SOURCE.read_bytes()), 1 << 20)
        self.assertLessEqual(len(SOURCE.read_text().splitlines()), 16384)
        self.assertLessEqual(len(document_value['functions']), 128)
        self.assertLessEqual(sum(len(f['blocks']) for f in document_value['functions']), 1536)
        self.assertLessEqual(sum(len(b['ops']) for f in document_value['functions'] for b in f['blocks']), 8192)
        for function in document_value['functions']:
            self.assertLessEqual(len(function['blocks']), 256)
            values = list(function['params'])
            for block in function['blocks']:
                values.extend(block['params'])
                for operation in block['ops']:
                    values.extend(operation['out'])
            self.assertLess(max(int(value['name'][1:]) for value in values), 2048)

    def test_complete_original_Code_AST_and_fixture_bytes_are_retained(self):
        self.assertEqual(sha256(FIXTURE.read_bytes()).hexdigest(), FIXTURE_SHA256)
        def class_node(raw):
            value = next(n for n in ast.parse(raw).body if isinstance(n, ast.ClassDef) and n.name == 'Code')
            value.body = [n for n in value.body if not isinstance(n, ast.FunctionDef) or n.name != '__new__']
            return ast.dump(value, include_attributes=False)
        self.assertEqual(class_node(FIXTURE.read_text()), class_node(inspect.getsource(reference)))

    def test_cold_admission_refuses_before_output(self):
        from tools.build_hia_machine_state import build
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            compiler, cold = root / 'compiler', root / 'cold.json'
            compiler.write_bytes(b'not a compiler')
            cold.write_text('{}')
            output = root / 'must-not-exist'
            with self.assertRaisesRegex(ValueError, 'completed matching native cold'):
                build(output, compiler, cold)
            self.assertFalse(output.exists())
            # The loader's generic factory contract does not observe a returned
            # object's overridable __class__ attribute.
            from hepta import hia_json_preflight_native as loader
            observations, factories = [], []
            class ForeignFactoryResult:
                @property
                def __class__(self):
                    observations.append('__class__')
                    raise AssertionError('generic factory result was observed')
            foreign = ForeignFactoryResult()
            image_raw = b'inert generic factory input'
            image = root / 'generic-image.bin'
            image.write_bytes(image_raw)
            image_sha = sha256(image_raw).hexdigest()
            source_sha = sha256(b'generic factory source').hexdigest()
            schema = 'hepta.hia.generic-factory-control.v1'
            manifest_raw = json.dumps({
                'schema': schema, 'source_sha256': source_sha,
                'image_path': image.name, 'image_sha256': image_sha,
                'compiler_sha256': '0' * 64,
            }).encode()
            def factory(actual_image, actual_sha):
                factories.append((actual_image, actual_sha))
                return foreign
            actual = loader._load_manifest.__wrapped__(
                str(root / 'generic-manifest.json'), manifest_raw,
                source_sha, schema, factory)
            self.assertIs(actual, foreign)
            self.assertEqual(factories, [(image_raw, image_sha)])
            self.assertEqual(observations, [])

    def test_unselected_and_subclasses_preserve_existing_owner(self):
        with patch.dict(os.environ, {SELECTOR: '', ENCODING_SELECTOR: ''}):
            self.assertEqual(type(reference.Code()), reference.Code)
            self.assertEqual(reference.native_implementation_identity(), b'')
        with patch.dict(os.environ, {SELECTOR: '/missing/state', ENCODING_SELECTOR: ''}):
            with self.assertRaisesRegex(reference.MachineEncodingError, 'requires the native instruction'):
                reference.Code()
            class OwnCode(reference.Code):
                pass
            self.assertEqual(type(OwnCode()), OwnCode)


class MachineStateNativeTests(unittest.TestCase):
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
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-machine-state-')
            cls.addClassCleanup(cls.temporary.cleanup)
            cls.folder = Path(cls.temporary.name)
        if cold:
            from tools.build_hia_machine_state import build
            from tools.build_hia_machine_encoding import build as build_encoding
            outer = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(outer['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
            cls.manifest = build(cls.folder / 'state', compiler, Path(cold))
            cls.encoding_manifest = build_encoding(cls.folder / 'encoding', compiler, Path(cold))
            cls.scope = 'MATCHING_SOURCE_COLD_BUILD'
        elif development:
            bundle = json.loads(Path(development).read_bytes())
            cls.manifest = Path(bundle['state_manifest']).resolve(strict=True)
            cls.encoding_manifest = Path(bundle['encoding_manifest']).resolve(strict=True)
            cls.scope = 'EXPLICIT_DEVELOPMENT_ONLY'
        else:
            raise unittest.SkipTest('requires explicit matching cold or development bundle')
        cls.native = installed_machine_state(str(cls.manifest))

    def selected(self):
        stack = ExitStack()
        stack.enter_context(patch.dict(os.environ, {
            SELECTOR: str(self.manifest), ENCODING_SELECTOR: str(self.encoding_manifest)}))
        for name, member in reference.Code.__dict__.items():
            if inspect.isfunction(member) and name != '__new__':
                stack.enter_context(patch.object(reference.Code, name,
                    side_effect=AssertionError('retained Code owner entered: ' + name)))
        def forbidden(*args, **kwargs):
            raise AssertionError('retained native bridge state owner entered')
        stack.enter_context(patch.object(reference.Code, 'offset', property(forbidden)))
        stack.enter_context(patch.object(reference, '_reg', forbidden))
        stack.enter_context(patch.object(NativeEncodedCode, '__init__', forbidden))
        stack.enter_context(patch.object(NativeEncodedCode, 'finalize', forbidden))
        return stack

    def save(self, name, value):
        (self.folder / name).write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')

    def test_all_original_instruction_cases_with_every_retained_state_owner_forbidden(self):
        from tests.test_hia_machine_encoding_native import cases, observe
        expected = [observe(oracle().Code, row) for row in cases()]
        self.native.calls.clear()
        actual = []
        with self.selected():
            for row, wanted in zip(cases(), expected):
                with self.subTest(case=row['id']):
                    result = observe(reference.Code, row)
                    actual.append({'id': row['id'], 'expected': wanted, 'actual': result})
                    self.assertEqual(result, wanted)
            code = reference.Code()
            self.assertEqual(code.offset, 0)
        self.assertEqual(set(self.native.calls), {'initialize', 'emit', 'label', 'finalize', 'offset', 'register'})
        self.save('original-instruction-observations.json', actual)

    def test_public_mutation_foreign_binding_arithmetic_and_copy_order(self):
        names = ('label-rebind', 'emit-rebind', 'double-offset-and-row-copy',
                 'labels-rebound-between-contains-and-get', 'relocation-live-iteration',
                 'register-map-binding', 'non-string-missing-label',
                 'invalid-fixup-shape', 'invalid-offset-arithmetic')
        expected = [mutable_observation(oracle().Code, name) for name in names]
        rows = []
        with self.selected():
            for name, wanted in zip(names, expected):
                with self.subTest(case=name):
                    actual = mutable_observation(reference.Code, name)
                    rows.append({'id': name, 'expected': wanted, 'actual': actual})
                    self.assertEqual(actual, wanted)
        from tests.test_hia_machine_encoding_native import observe_foreign_alu
        alu_rows = [([False, False, False], 7, False),
                    ([False, True, False], 7, False),
                    ([False, False, True], 7, False),
                    ([False, True, False], 128, False),
                    ([False, False, False], 7, True)]
        expected_alu = [observe_foreign_alu(oracle().Code, *row) for row in alu_rows]
        with self.selected():
            for number, (row, wanted) in enumerate(zip(alu_rows, expected_alu)):
                with self.subTest(foreign_alu=row):
                    actual = observe_foreign_alu(reference.Code, *row)
                    rows.append({'id': 'foreign-alu-' + str(number),
                                 'expected': wanted, 'actual': actual})
                    self.assertEqual(actual, wanted)
        self.save('mutable-observations.json', rows)

    def test_actual_64MiB_and_signed_rel32_boundaries(self):
        values = (-(1 << 31) - 1, -(1 << 31), -1, 0, (1 << 31) - 1,
                  1 << 31, -(1 << 96) - (1 << 31))
        def observe(factory, value):
            code = factory()
            code.data = bytearray(4)
            code.fixups = [(0, 'x')]
            code.labels = {'x': value + 4}
            try:
                raw, rows = code.finalize()
                return {'bytes': raw.hex(), 'rows': rows, 'data': code.data.hex()}
            except BaseException as exc:
                return {'error': exception(exc), 'data': code.data.hex()}
        expected = [observe(oracle().Code, value) for value in values]
        with self.selected():
            for value, wanted in zip(values, expected):
                with self.subTest(value=value):
                    self.assertEqual(observe(reference.Code, value), wanted)
            code = reference.Code()
            code.data = bytearray(64 * 1024 * 1024)
            self.assertIsNone(code.emit(b''))
            with self.assertRaisesRegex(reference.MachineEncodingError, 'code byte limit'):
                code.emit(b'x')
            self.assertEqual(len(code.data), 67108864)
            raw, rows = code.finalize()
            self.assertEqual(len(raw), 67108864)
            self.assertEqual(sha256(raw).hexdigest(), sha256(code.data).hexdigest())
            self.assertEqual(rows, [])
            code.data.append(0)
            with self.assertRaisesRegex(reference.MachineEncodingError, 'code byte limit'):
                code.finalize()

    def test_foreign_metaclass_membership_uses_no_hash_and_keeps_original_truth_order(self):
        def observe(factory):
            events = []
            class Truth:
                def __bool__(self):
                    events.append(['truth'])
                    return True
            class Meta(type):
                def __hash__(cls):
                    raise AssertionError('type admission hashed a foreign class')
                def __eq__(cls, other):
                    events.append(['type-equality', other.__name__])
                    return Truth()
            class BytesLike(metaclass=Meta):
                def __len__(self):
                    events.append(['length'])
                    return 1
                def __iter__(self):
                    events.append(['iterate'])
                    return iter([65])
            code = factory()
            try:
                code.emit(BytesLike())
                return {'events': events, 'bytes': code.data.hex(), 'error': None}
            except BaseException as exc:
                return {'events': events, 'bytes': code.data.hex(), 'error': exception(exc)}
        expected = observe(oracle().Code)
        with self.selected():
            actual = observe(reference.Code)
        self.assertEqual(actual, expected)
        self.save('metaclass-observations.json', {'expected': expected, 'actual': actual})

    def test_backend_identity_and_both_selectors_are_pinned_across_emit(self):
        from hepta import hia_program_native as backend
        from hepta.hia_program import verify_program
        from tests.test_hia_machine_plan import call_document
        checked = verify_program(call_document())
        with patch.dict(os.environ, {SELECTOR: '', ENCODING_SELECTOR: ''}):
            original = backend.emit_program_machine(checked)
        with self.selected():
            current = backend.emit_program_machine(checked)
        self.assertEqual(current.object_bytes, original.object_bytes)
        self.assertNotEqual(current.implementation_sha256, original.implementation_sha256)
        old_render = backend._Emitter.render
        def changing_render(emitter):
            os.environ[SELECTOR] = '/missing/state-after-pin'
            os.environ[ENCODING_SELECTOR] = '/missing/encoding-after-pin'
            return old_render(emitter)
        with self.selected(), patch.object(backend._Emitter, 'render', changing_render):
            repeated = backend.emit_program_machine(checked)
        self.assertEqual(repeated.object_bytes, current.object_bytes)
        self.assertEqual(repeated.implementation_sha256, current.implementation_sha256)
        with self.selected():
            assert_primitive_bridge_identity_bound(
                self, backend, ('hia_machine_state_native.py', 'hia_json_wire_native.py', 'hia_machine_transport.py'))
            from hepta import hia_machine_encoding_native as encoding_bridge
            from hepta import hia_machine_state_native as state_bridge
            self.save('source-admission-window.json', assert_scope_source_admission_bound(
                self, backend, checked, (encoding_bridge, state_bridge)))

    def test_malformed_ack_and_failed_effect_cannot_be_replayed(self):
        code = oracle().Code()
        session = MachineStateSession(self.native, code, 3, 'x')
        self.assertEqual(session.step(), 1)
        before = bytes(session.workspace)
        bad = struct.pack('<10Q', MAGIC, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        self.assertEqual(session.step(bad), 0xfffffffd)
        self.assertEqual(bytes(session.workspace), before)
        with self.assertRaisesRegex(RuntimeError, 'no unconsumed'):
            session.observe()
        self.assertEqual(code.labels, {})
        events = []
        class FailingLabels(dict):
            def __setitem__(self, key, value):
                events.append((key, value))
                super().__setitem__(key, value)
                raise OSError('original partial side effect')
        code.labels = FailingLabels()
        session = MachineStateSession(self.native, code, 3, 'x')
        status = session.step()
        with self.assertRaisesRegex(OSError, 'original partial side effect'):
            while status == 1:
                session.observe()
                status = session.step()
        self.assertEqual(events, [('x', 0)])
        for action in (session.observe, session.step):
            with self.assertRaises(RuntimeError):
                action()
        self.assertEqual(events, [('x', 0)])
        self.assertEqual(code.labels, {'x': 0})
        assert_terminal_after_native_bookkeeping_error(
            self, self.native, lambda: MachineStateSession(self.native, oracle().Code(), 3, 'x'))

    def test_warm_image_rechecks_package_source(self):
        from hepta import hia_machine_state_native as bridge
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / 'machine_state.hepta'
            source.write_bytes(SOURCE.read_bytes())
            with patch.object(bridge, 'SOURCE', source):
                self.assertIs(installed_machine_state(str(self.manifest)), self.native)
                source.write_bytes(source.read_bytes() + b'\n')
                with self.assertRaisesRegex(ValueError, 'source identity mismatch'):
                    installed_machine_state(str(self.manifest))
                source.unlink()
                with self.assertRaises(FileNotFoundError):
                    installed_machine_state(str(self.manifest))

    def test_actual_installed_wheel_uses_HIA_state_without_authoring_or_old_state(self):
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
            raise AssertionError('installed state imported authoring tools')
sys.meta_path.insert(0,NoTools())
from hepta import hia_machine_x64 as m
from hepta.hia_machine_encoding_native import NativeEncodedCode
from hepta.hia_machine_state_native import SOURCE,installed_machine_state
assert Path(sys.argv[1]) in SOURCE.parents
def forbidden(*a,**k):raise AssertionError('retained state or instruction entered')
for name,member in tuple(m.Code.__dict__.items()):
    if inspect.isfunction(member) and name!='__new__':setattr(m.Code,name,forbidden)
m.Code.offset=property(forbidden)
m._reg=forbidden
NativeEncodedCode.__init__=forbidden
NativeEncodedCode.finalize=forbidden
os.environ['HEPTA_HIA_MACHINE_ENCODING_MANIFEST']=sys.argv[2]
os.environ['HEPTA_HIA_MACHINE_STATE_MANIFEST']=sys.argv[3]
c=m.Code(scratch_registers={'r10':'r11','r11':'r10'})
c.label('a');c.jmp('z');c.mov_imm('r10',42);c.label('z');c.ret()
assert c.offset==16
raw,relocations=c.finalize()
assert raw.hex()=='e90a00000049bb2a00000000000000c3'
assert relocations==[] and c.finalize()[0]==raw
c.data[0]=0x90
assert c.finalize()[0][0]==0x90
owner=installed_machine_state(sys.argv[3])
assert all(owner.calls[k]>0 for k in ('initialize','emit','label','offset','register','finalize'))
print(json.dumps({'status':'INSTALLED_NATIVE_MACHINE_STATE_PASS','native_calls':dict(owner.calls),
 'source':str(SOURCE),'image_sha256':owner.image_sha256,
 'isolated_without_site':bool(sys.flags.isolated and sys.flags.no_site),
 'empty_PATH':os.environ['PATH']=='','authoring_forbidden':True,'retained_state_forbidden':True}))
'''
        script = case / 'installed-control.py'
        script.write_text(child)
        env = {k: v for k, v in os.environ.items() if not k.startswith('HEPTA_HIA_')}
        env.update(PATH='', PYTHONPATH='')
        result = command([sys.executable, '-I', '-S', '-B', str(script), str(installed),
                          str(self.encoding_manifest), str(self.manifest)], 'installed-execution', env=env)
        report = json.loads(result.stdout)
        self.assertEqual(report['status'], 'INSTALLED_NATIVE_MACHINE_STATE_PASS')
        self.assertTrue(report['isolated_without_site'])
        self.save('installed-control-report.json', report)


if __name__ == '__main__':
    unittest.main()
