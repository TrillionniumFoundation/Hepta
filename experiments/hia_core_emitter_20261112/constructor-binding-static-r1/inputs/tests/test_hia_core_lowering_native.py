"""Independent ordinary-entry, ABI and installed tests for HIA Core lowering."""
from __future__ import annotations
import ast
from collections import Counter
from contextlib import ExitStack
import ctypes
from dataclasses import fields
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

from hepta import hia_program_native as backend
from hepta.hia_core_lowering_native import NativeCoreLowering, LoweringSession, FRAME, MAGIC, ABI
from hepta.hia_core_lowering_selection import (
    SELECTOR, ABI_SOURCE, checked_abi, source_names, installed_core_lowering,
    native_core_lowering_scope, active_core_lowering)
from hepta.hia_json_preflight_native import _source_resource_path

ROOT = Path(__file__).resolve().parents[1]
DEVELOPMENT = 'HEPTA_HIA_CORE_LOWERING_DEVELOPMENT_MANIFEST'
COLD = 'HEPTA_HIA_CORE_LOWERING_COLD_REPORT'
EVIDENCE = 'HEPTA_HIA_CORE_LOWERING_FIXTURE_EVIDENCE'
FIXTURE_SHA = '8f0be8c06e932fedbdd5973591310440a97e85a0c3b88ba9bc5ca95035810185'
HELPERS = ('_reject', '_words', '_bounds', '_normalize', '_prologue')


def recorded(function, *args):
    try:
        return {'value': function(*args)}
    except BaseException as exc:
        return {'exception_type': type(exc), 'exception_args': exc.args}


def comparable(machine):
    return {field.name: getattr(machine, field.name) for field in fields(machine)
            if field.name != 'implementation_sha256'}


def original_nodes():
    raw = (Path(__file__).with_name('fixtures') / 'hia_program_native_608.py.txt').read_bytes()
    if sha256(raw).hexdigest() != FIXTURE_SHA:
        raise AssertionError('complete original lowering fixture differs')
    return ast.parse(raw)



def original_binding_targets():
    # Compile the complete frozen definitions solely as an independent Python
    # binder oracle. Every call below has invalid arguments and must fail before
    # any original method/helper body can execute.
    names = {'_Function', '_Emitter', *HELPERS}
    nodes = [node for node in original_nodes().body
             if isinstance(node, (ast.ClassDef, ast.FunctionDef)) and node.name in names]
    namespace = {'__name__': 'hia_independent_original_binding'}
    exec(compile(ast.Module(body=nodes, type_ignores=[]),
                 '<hia-original-binding-oracle>', 'exec'), namespace)
    return namespace


def invalid_binding_arguments(function):
    parameters = tuple(inspect.signature(function).parameters.values())
    if not all(p.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD for p in parameters):
        raise AssertionError('original binding control needs its exact positional signatures')
    marker = object()
    names = tuple(p.name for p in parameters)
    required = sum(p.default is inspect.Parameter.empty for p in parameters)
    full = (marker,) * len(parameters)
    cases = [
        ('extra-positional', full + (marker,), {}),
        ('unknown-keyword', full, {'unknown_argument': marker}),
        ('implicit-self-keyword', full, {'self': marker}),
        ('class-keyword', full, {'cls': marker}),
        ('extra-and-unknown', full + (marker,), {'unknown_argument': marker}),
    ]
    for count in range(required):
        cases.append(('missing-' + str(count), full[:count], {}))
    for name in names:
        cases.append(('duplicate-' + name, full, {name: marker}))
    if required:
        values = dict.fromkeys(names, marker)
        del values[names[required - 1]]
        cases.append(('missing-required-keyword', (), values))
    if names:
        first = names[0]
        cases.extend([
            ('unknown-before-duplicate', full, {'unknown_argument': marker, first: marker}),
            ('duplicate-before-unknown', full, {first: marker, 'unknown_argument': marker}),
            ('similar-unknown-keyword', full, {first + '_': marker}),
        ])
    return cases


def selected_guard(manifest):
    stack = ExitStack()
    stack.enter_context(patch.dict(os.environ, {SELECTOR: str(manifest)}))
    for cls in (backend._Function, backend._Emitter):
        for name, method in cls.__dict__.items():
            if inspect.isfunction(method) and name != '__new__':
                stack.enter_context(patch.object(cls, name,
                    side_effect=AssertionError('retained lowering control entered: ' + cls.__name__ + '.' + name)))
    for name in HELPERS:
        legacy = '_reference' + name
        original = getattr(backend, legacy)
        def guard(*args, _name=legacy, _original=original, **kwargs):
            if active_core_lowering() is not None:
                raise AssertionError('retained helper entered captured lowering: ' + _name)
            return _original(*args, **kwargs)
        stack.enter_context(patch.object(backend, legacy, guard))
    return stack


class CoreLoweringSourceTests(unittest.TestCase):
    def test_complete_original_Function_and_five_helpers_are_independent(self):
        original = original_nodes()
        current = ast.parse(inspect.getsource(backend))
        # Keep the original v1 method ID while extending its whole-body oracle
        # to the six newly owned Emitter methods.
        for class_name, count in (('_Function', 22), ('_Emitter', 6)):
            before = next(n for n in original.body if isinstance(n, ast.ClassDef) and n.name == class_name)
            after = next(n for n in current.body if isinstance(n, ast.ClassDef) and n.name == class_name)
            additions = [n for n in after.body if isinstance(n, ast.FunctionDef) and n.name == '__new__']
            self.assertEqual(len(additions), 1)
            after.body = [n for n in after.body if n not in additions]
            self.assertEqual(len([n for n in before.body if isinstance(n, ast.FunctionDef)]), count)
            self.assertEqual(ast.dump(before), ast.dump(after))
        for name in HELPERS:
            wanted = next(n for n in original.body if isinstance(n, ast.FunctionDef) and n.name == name)
            retained = next(n for n in current.body if isinstance(n, ast.FunctionDef) and n.name == '_reference' + name)
            retained.name = name
            self.assertEqual(ast.dump(wanted), ast.dump(retained))
        import hepta.hia_core_lowering_native as primitive
        tree = ast.parse(inspect.getsource(primitive))
        imported = [n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
        self.assertFalse(any(name and name.startswith('tools') for name in imported))

    def test_current_32_sources_keep_original_Core_caps_and_literal_VM(self):
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        abi = checked_abi(_source_resource_path(ABI_SOURCE).read_bytes())
        names = source_names(abi)
        # The historical test ID remains fixed; v2 adds seven real units.
        self.assertEqual(len(names), 39)
        programs = []
        for name in names:
            raw = _source_resource_path(name).read_bytes()
            self.assertLessEqual(len(raw), 1 << 20)
            self.assertLessEqual(len(raw.splitlines()), 16384)
            program = assemble_program(raw)
            document = program.as_dict()
            self.assertEqual(render_assembly(document).encode(), raw)
            functions = document['functions']
            blocks = [b for f in functions for b in f['blocks']]
            self.assertLessEqual(len(functions), 128)
            self.assertLessEqual(len(blocks), 1536)
            self.assertLessEqual(sum(len(b['ops']) + 1 for b in blocks), 8192)
            for function in functions:
                self.assertLessEqual(len(function['blocks']), 256)
                self.assertLessEqual(len(function['params']), 16)
                definitions = {p['name'] for p in function['params']}
                for block in function['blocks']:
                    definitions.update(p['name'] for p in block['params'])
                    for op in block['ops']:
                        definitions.update(p['name'] for p in op['out'])
                        self.assertLessEqual(len(op.get('args', [])), 16)
                self.assertLessEqual(len(definitions), 2048)
            programs.append(program)
        resources = []
        class VMImage:
            def __init__(self, program):
                self.program = program
            def _entry(self, source, size, output, output_size, workspace, workspace_size):
                packet = ctypes.string_at(source, size)
                owners = [_Owner(-1, bytearray(packet)),
                          _Owner(-2, bytearray(ctypes.string_at(output, output_size))),
                          _Owner(-3, bytearray(ctypes.string_at(workspace, workspace_size)))]
                machine = _Machine(self.program, 4_000_000, 16 << 20, None, 128)
                function = self.program.as_dict()['functions'][0]
                result = machine.invoke(function, [_View(owners[0], False),
                    _View(owners[1], True), _View(owners[2], True)])[0]
                if bytes(owners[0].data) != packet:
                    raise AssertionError('lowering wrote its readonly packet')
                for pointer, owner in ((output, owners[1]), (workspace, owners[2])):
                    ctypes.memmove(pointer, bytes(owner.data), len(owner.data))
                resources.append(machine.resources())
                return result
        owner = NativeCoreLowering([VMImage(p) for p in programs[1:]], VMImage(programs[0]), abi, vars(backend))
        with patch.dict(os.environ, {SELECTOR: ''}):
            for name, arguments in [('_words', ('mutbuf',)), ('_words', ('chain',)),
                                    ('_bounds', ('i8',)), ('_bounds', ('u64',)),
                                    ('_reject', ('deliberate', 'E_CORE_CONTROL'))]:
                self.assertEqual(recorded(owner.invoke, name, arguments),
                                 recorded(getattr(backend, '_reference' + name), *arguments))
        self.assertTrue(resources)
        self.assertTrue(all(r['live_owners'] == r['live_local_loans'] == 0 for r in resources))

    def test_unqualified_cold_refuses_before_output_creation(self):
        from tools.build_hia_core_lowering import build
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            compiler, cold = root / 'compiler', root / 'cold'
            compiler.write_bytes(b'explicitly-not-qualified')
            cold.write_text('{"status":"DEVELOPMENT_ONLY"}')
            with self.assertRaisesRegex(ValueError, 'completed matching native cold'):
                build(root / 'must-not-create' / 'build', compiler, cold)
            self.assertFalse((root / 'must-not-create').exists())

    def test_unselected_constructor_subclass_and_early_target_errors_stay_original(self):
        from hepta.hia_program import verify_program
        from tests.test_hia_program_native import minimal_document
        program = verify_program(minimal_document())
        with patch.dict(os.environ, {SELECTOR: ''}):
            image = backend.emit_program_machine(program)
            emitter = backend._Emitter(program.as_dict(), set(image.exports))
            self.assertIs(type(backend._Function(emitter, program.as_dict()['functions'][0], 0)), backend._Function)
            wanted = recorded(backend.emit_program_machine, program)
        class Foreign(backend._Function):
            def __init__(self, parent, fn, index):
                self.marker = (parent, fn, index)
        class ForeignEmitter(backend._Emitter):
            def __init__(self, document, exports):
                self.marker = (document, exports)
        with patch.dict(os.environ, {SELECTOR: '/missing/explicit-core-lowering-manifest'}):
            foreign = Foreign(None, None, 7)
            self.assertEqual(foreign.marker, (None, None, 7))
            emitter = ForeignEmitter({'foreign': True}, {'f0'})
            self.assertEqual(emitter.marker, ({'foreign': True}, {'f0'}))
            # The inherited dispatcher must not bind the original class's
            # signature before allowing a foreign subclass to run its own init.
            # These calls must not observe even a missing explicit selector.
            for base in (backend._Function, backend._Emitter):
                class Positional(base):
                    def __init__(self, value):
                        self.marker = value
                class KeywordOnly(base):
                    def __init__(self, *, value):
                        self.marker = value
                class ClassKeyword(base):
                    def __init__(self, *, cls):
                        self.marker = cls
                marker = object()
                self.assertIs(Positional(marker).marker, marker)
                self.assertIs(KeywordOnly(value=marker).marker, marker)
                self.assertIs(ClassKeyword(cls=marker).marker, marker)
            with self.assertRaises(FileNotFoundError):
                backend.emit_program_machine(program)
            with self.assertRaisesRegex(backend.HIAProgramNativeRejected, 'E_HIA_PROGRAM_TARGET'):
                backend.emit_program_machine(program, target='not-the-accepted-target')
        self.assertIn('value', wanted)
        reference = original_binding_targets()
        with patch.dict(os.environ, {SELECTOR: '/missing/explicit-core-lowering-manifest'}):
            with patch('hepta.hia_core_lowering_selection.selected_core_lowering',
                       side_effect=AssertionError('invalid arguments observed the selector')):
                for name in ('_Function', '_Emitter'):
                    original, actual = reference[name], getattr(backend, name)
                    for label, arguments, keywords in invalid_binding_arguments(original):
                        with self.subTest(constructor=name, shape=label):
                            expected = recorded(lambda: original(*arguments, **keywords))
                            self.assertIs(expected.get('exception_type'), TypeError)
                            observed = recorded(lambda: actual(*arguments, **keywords))
                            self.assertEqual(observed, expected)


class CoreLoweringNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        development, cold = os.environ.get(DEVELOPMENT), os.environ.get(COLD)
        if development and cold:
            raise AssertionError('development image cannot override requested cold')
        evidence = os.environ.get(EVIDENCE)
        if evidence:
            cls.folder = Path(evidence).resolve()
            cls.folder.mkdir(parents=True, exist_ok=False)
        else:
            temporary = tempfile.TemporaryDirectory(prefix='hia-core-lowering-')
            cls.addClassCleanup(temporary.cleanup)
            cls.folder = Path(temporary.name)
        if cold:
            from tools.build_hia_core_lowering import build
            report = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(report['nested_report']).read_bytes())
            cls.manifest = build(cls.folder / 'qualified', Path(nested['generations'][-1]['produced_image']), Path(cold))
            cls.scope = 'MATCHING_SOURCE_COLD_BUILD'
        elif development:
            cls.manifest = Path(development).resolve(strict=True)
            cls.scope = 'EXPLICIT_DEVELOPMENT_ONLY'
        else:
            raise unittest.SkipTest('requires current cold report or explicit development bundle')
        cls.owner = installed_core_lowering(str(cls.manifest), vars(backend))

    def test_ordinary_backend_is_native_with_complete_metadata_and_no_retained_Function(self):
        from hepta.hia_program import verify_program
        from tests.test_hia_program_native import minimal_document
        from tests.test_hia_program_native_review import _empty_memory_program
        from tools.qualify_hia_program import qualification_program
        documents = [minimal_document(), _empty_memory_program(), qualification_program()]
        with patch.dict(os.environ, {SELECTOR: ''}):
            expected = [backend.emit_program_machine(verify_program(doc)) for doc in documents]
        for doc, wanted in zip(documents, expected):
            with selected_guard(self.manifest):
                actual = backend.emit_program_machine(verify_program(doc))
            self.assertEqual(comparable(actual), comparable(wanted))
            self.assertNotEqual(actual.implementation_sha256, wanted.implementation_sha256)
        reference = original_binding_targets()
        factories = {'_Function': self.owner.function_class,
                     '_Emitter': self.owner.emitter_class}
        for name, factory in factories.items():
            original_type = reference[name]
            native_type = factory(getattr(backend, name))
            original_receiver = object.__new__(original_type)
            native_receiver = object.__new__(native_type)
            for method_name, method in vars(original_type).items():
                if not inspect.isfunction(method):
                    continue
                original = types.MethodType(method, original_receiver)
                actual = getattr(native_receiver, method_name)
                with patch.object(self.owner, 'invoke',
                                  side_effect=AssertionError('invalid binding entered HIA')):
                    for label, arguments, keywords in invalid_binding_arguments(original):
                        with self.subTest(owner=name, method=method_name, shape=label):
                            expected = recorded(lambda: original(*arguments, **keywords))
                            self.assertIs(expected.get('exception_type'), TypeError)
                            self.assertEqual(recorded(lambda: actual(*arguments, **keywords)), expected)

    def test_five_helpers_and_native_literal_owner_keep_errors_and_values(self):
        for typ in (*backend.WIDTHS, 'bool', 'unit', 'buffer', 'readbuf', 'mutbuf', 'chain', 'missing', None, []):
            for name in ('_words', '_bounds'):
                with self.subTest(name=name, typ=typ):
                    wanted = recorded(getattr(backend, '_reference' + name), typ)
                    self.assertEqual(recorded(self.owner.invoke, name, (typ,)), wanted)
        self.assertEqual(recorded(self.owner.invoke, '_reject', ('message', 'E_NATIVE')),
                         recorded(backend._reference_reject, 'message', 'E_NATIVE'))
        literal = self.owner.invoke('_native_globals', ())
        self.assertEqual(literal, {name: getattr(backend, name) for name in (
            'WIDTHS', 'BYTE_RESOURCES', 'MAX_TEXT_BYTES', 'MAX_FRAME_BYTES')})
        class Recorder:
            def __init__(self):
                self.calls = []
            def __getattr__(self, name):
                def call(*args):
                    self.calls.append((name, args))
                return call
        for typ in ('i8', 'u32', 'u64', 'bool', 'unit', 'chain'):
            old, native = Recorder(), Recorder()
            backend._reference_normalize(old, 'rax', typ)
            self.owner.invoke('_normalize', (native, 'rax', typ))
            self.assertEqual(native.calls, old.calls)
        old, native = Recorder(), Recorder()
        backend._reference_prologue(old, 8193)
        self.owner.invoke('_prologue', (native, 8193))
        self.assertEqual(native.calls, old.calls)
        reference = original_binding_targets()
        with patch.object(self.owner, 'invoke',
                          side_effect=AssertionError('invalid helper binding entered HIA')):
            for name in HELPERS:
                original, actual = reference[name], self.owner._helpers[name]
                for label, arguments, keywords in invalid_binding_arguments(original):
                    with self.subTest(helper=name, shape=label):
                        expected = recorded(lambda: original(*arguments, **keywords))
                        self.assertIs(expected.get('exception_type'), TypeError)
                        self.assertEqual(recorded(lambda: actual(*arguments, **keywords)), expected)

    def test_exact_foreign_store_binding_and_nested_native_invocation_order(self):
        def observe(native, reenter):
            events = []
            class Code:
                def __getattribute__(self, name):
                    if name == 'store':
                        events.append(['bind-store'])
                    return object.__getattribute__(self, name)
                def store(self, *arguments):
                    events.append(['old-store', *arguments])
                    if reenter:
                        result = self_owner.invoke('_words', ('mutbuf',)) if native else backend._reference_words('mutbuf')
                        events.append(['nested', result])
            class Slots(dict):
                def __getitem__(self, key):
                    events.append(['slot', key])
                    return super().__getitem__(key)
            code = Code()
            class Word:
                def __mul__(self, value):
                    events.append(['multiply', value])
                    code.store = lambda *args: events.append(['new-store', *args])
                    return 8
            receiver = types.SimpleNamespace(c=code, value_registers={}, slots=Slots(x=-24))
            self_owner = self.owner
            if native:
                result = recorded(self.owner.invoke, '_Function.store', (receiver, 'x', 'rax', Word()))
            else:
                result = recorded(backend._Function.store, receiver, 'x', 'rax', Word())
            return result, events
        for nested in (False, True):
            self.assertEqual(observe(True, nested), observe(False, nested))

    def test_protocol_buffers_canaries_and_single_use_observations(self):
        mode = self.owner.modes['_words']['number']
        for wrong in (b'', b'x' * 127, b'x' * 129, FRAME.pack(*([0] * 16))):
            session = LoweringSession(self.owner, mode, ('mutbuf',))
            with self.assertRaises((TypeError, RuntimeError)):
                session.step(wrong)
            with self.assertRaises(RuntimeError):
                session.observe()
            with self.assertRaises(RuntimeError):
                session.step(session.initial)
        session = LoweringSession(self.owner, mode, ('mutbuf',))
        self.assertEqual(session.step(session.initial), 1)
        ack = session.observe()
        with self.assertRaises(RuntimeError):
            session.observe()
        with self.assertRaises(RuntimeError):
            session.step(ack)
        output_bytes, workspace_bytes = self.owner.output_bytes, self.owner.workspace_bytes
        for source_size, out_size, work_size in ((127, output_bytes, workspace_bytes),
                (128, output_bytes - 1, workspace_bytes), (128, output_bytes, workspace_bytes - 1)):
            session = LoweringSession(self.owner, mode, ('mutbuf',))
            source = ctypes.create_string_buffer(session.initial)
            output = ctypes.create_string_buffer(b'\xa5' * (output_bytes + 32))
            workspace = ctypes.create_string_buffer(b'\0' * (workspace_bytes + 32))
            before_source = bytes(source)
            result = self.owner.images[0]._entry(source, source_size,
                ctypes.byref(output, 16), out_size, ctypes.byref(workspace, 16), work_size)
            self.assertEqual(result, ABI)
            self.assertEqual(bytes(source), before_source)
            self.assertEqual(bytes(output)[:16], b'\xa5' * 16)
            self.assertEqual(bytes(output)[16 + output_bytes:32 + output_bytes], b'\xa5' * 16)
            self.assertEqual(bytes(workspace)[:16], b'\0' * 16)
            self.assertEqual(bytes(workspace)[16 + workspace_bytes:32 + workspace_bytes], b'\0' * 16)

    def test_actual_native_return_then_foreign_failure_closes_every_continuation(self):
        mode = self.owner.modes['_words']['number']
        image = self.owner.images[0]
        real = image._entry
        for exception in (KeyboardInterrupt, SystemExit, MemoryError, RuntimeError):
            entered = []
            def fail(*args, _exception=exception):
                entered.append(real(*args))
                raise _exception('after actual native entry')
            session = LoweringSession(self.owner, mode, ('mutbuf',))
            with patch.object(image, '_entry', fail):
                with self.assertRaises(exception):
                    session.step(session.initial)
            self.assertTrue(entered)
            for action in (lambda: session.step(session.initial), session.observe, session.handoff, session.resume):
                with self.assertRaises(RuntimeError):
                    action()
            self.assertEqual(len(entered), 1)
        events = []
        class Receiver:
            @property
            def value_registers(self):
                events.append('observed')
                raise KeyboardInterrupt('foreign observation')
        session = LoweringSession(self.owner, self.owner.modes['_Function.store']['number'],
                                  (Receiver(), 'x', 'rax', 0))
        with self.assertRaises(KeyboardInterrupt):
            session.run()
        for action in (session.observe, lambda: session.step(session.initial)):
            with self.assertRaises(RuntimeError):
                action()
        self.assertEqual(events, ['observed'])

    def test_capture_identity_reentrancy_and_all_bridge_dependencies(self):
        from hepta.hia_program import verify_program
        from tests.test_hia_program_native import minimal_document
        program = verify_program(minimal_document())
        with selected_guard(self.manifest):
            wanted = backend.emit_program_machine(program)
            # The retained Emitter.render is now forbidden too. Observe at the
            # original imported callback, inside actual native __init__.
            from hepta import hia_machine_plan
            original_options, callbacks = hia_machine_plan.code_options, []
            def code_options(plan):
                self.assertIsNotNone(active_core_lowering())
                callbacks.append('after-captured-owner')
                os.environ[SELECTOR] = '/missing/changed-after-capture'
                return original_options(plan)
            with patch.object(hia_machine_plan, 'code_options', code_options):
                actual = backend.emit_program_machine(program)
            self.assertEqual(callbacks, ['after-captured-owner'])
        self.assertEqual(actual, wanted)
        with patch.dict(os.environ, {SELECTOR: ''}), native_core_lowering_scope(vars(backend)):
            os.environ[SELECTOR] = str(self.manifest)
            self.assertIsNone(active_core_lowering())
            with native_core_lowering_scope(vars(backend)):
                self.assertIsNone(active_core_lowering())
        original_read = Path.read_bytes
        with patch.dict(os.environ, {SELECTOR: str(self.manifest)}):
            initial = backend._implementation_hash()
            for name in ('hia_core_lowering_native.py', 'hia_core_lowering_selection.py'):
                def changed(path, _name=name):
                    raw = original_read(path)
                    return raw + b'\n# identity observation\n' if path == ROOT / 'hepta' / _name else raw
                with patch.object(Path, 'read_bytes', changed):
                    self.assertNotEqual(backend._implementation_hash(), initial)

    def test_warm_source_ABI_and_fresh_manifest_key_must_be_readmitted(self):
        import hepta.hia_core_lowering_selection as selection
        from tools.qualify_hia_core_lowering_callers import copy_bundle
        resolver = selection._source_resource_path
        abi_raw = resolver(ABI_SOURCE).read_bytes()
        last = source_names(checked_abi(abi_raw))[-1]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in (ABI_SOURCE, last):
                alternate = root / Path(relative).name
                original = resolver(relative).read_bytes()
                alternate.write_bytes(original + b'\n')
                def resolve(name, _relative=relative):
                    return alternate if name == _relative else resolver(name)
                with patch.object(selection, '_source_resource_path', resolve):
                    with self.assertRaisesRegex(ValueError, 'source identity'):
                        installed_core_lowering(str(self.manifest), vars(backend))
                    alternate.unlink()
                    with self.assertRaises(FileNotFoundError):
                        installed_core_lowering(str(self.manifest), vars(backend))
            copied = copy_bundle(self.manifest, root / 'bundle')
            installed_core_lowering(str(copied), vars(backend))
            outer = json.loads(copied.read_bytes())
            unit = copied.parent / outer['unit_manifests']['core_lowering_030']
            spec = json.loads(unit.read_bytes())
            corrupt = unit.parent / 'fresh-corrupt-image.bin'
            corrupt.write_bytes(b'not the admitted image')
            spec['image_path'] = corrupt.name
            unit.write_text(json.dumps(spec))
            with self.assertRaises(ValueError):
                installed_core_lowering(str(copied), vars(backend))

    def test_actual_installed_wheel_uses_complete_bundle_without_authoring(self):
        from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, PUBLICATION_BUILD_FILES
        from tests.test_hia_program_native import minimal_document
        case = self.folder / 'installed-control'
        case.mkdir()
        source = case / 'source'
        source.mkdir()
        shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        resources = tuple('docs/' + n for n in DISCOVERY_FILES) + NATIVE_SOURCE_FILES + PUBLICATION_BUILD_FILES
        for name in (*resources, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        expected = {'python': {p.relative_to(ROOT).as_posix(): sha256(p.read_bytes()).hexdigest()
                              for p in sorted((ROOT / 'hepta').rglob('*.py')) if '_data' not in p.parts},
                    'resources': {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in resources},
                    'document': minimal_document()}
        request = case / 'expected.json'
        request.write_text(json.dumps(expected, sort_keys=True))
        packaging = os.environ.get('HEPTA_HIA_TEST_PACKAGING_PYTHON', sys.executable)
        wheels, installed = case / 'wheels', case / 'installed'
        processes = []
        def run(arguments, label, env=None):
            result = subprocess.run(arguments, cwd=case, env=env, capture_output=True, timeout=120)
            (case / (label + '.stdout')).write_bytes(result.stdout)
            (case / (label + '.stderr')).write_bytes(result.stderr)
            processes.append({'argv': arguments, 'returncode': result.returncode,
                              'stdout_sha256': sha256(result.stdout).hexdigest(),
                              'stderr_sha256': sha256(result.stderr).hexdigest()})
            (case / 'processes.json').write_text(json.dumps(processes, indent=2) + '\n')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return result
        run([packaging, '-B', '-m', 'pip', 'wheel', '--no-cache-dir', '--no-deps', '--no-index',
             '--no-build-isolation', '--wheel-dir', str(wheels), str(source)], 'wheel-build')
        wheel, = wheels.glob('*.whl')
        run([packaging, '-B', '-m', 'pip', 'install', '--no-cache-dir', '--no-deps', '--no-index',
             '--target', str(installed), str(wheel)], 'wheel-install')
        script = case / 'installed-child.py'
        script.write_text(INSTALLED_CHILD)
        env = {k: v for k, v in os.environ.items() if not k.startswith('HEPTA_HIA_') and k != 'PYTHONPATH'}
        env['PATH'] = ''
        result = run([sys.executable, '-I', '-S', '-B', str(script), str(installed),
                      str(self.manifest), str(request)], 'installed-execution', env)
        observed = json.loads(result.stdout)
        self.assertEqual(observed['status'], 'INSTALLED_CORE_LOWERING_PASS')
        self.assertEqual(observed['units'], 39)
        (case / 'report.json').write_text(json.dumps(observed, indent=2, sort_keys=True) + '\n')

    def test_Emitter_constructor_keeps_keyword_expansion_and_partial_assignments(self):
        from hepta import hia_machine_plan
        def observation(native, failure):
            events = []
            document = {'functions': [{'name': 'f0'}]}
            allowed = {'f0'}
            class Receiver:
                def __setattr__(self, name, value):
                    events.append(('set', name))
                    object.__setattr__(self, name, value)
            receiver = Receiver()
            class Plan:
                def get(self, key, default):
                    events.append(('plan.get', key, default))
                    return 32
            plan = Plan()
            class Options:
                def keys(self):
                    events.append(('options.keys',))
                    if failure == 'keys':
                        raise TypeError('foreign keys refused')
                    return ['scratch']
                def __getitem__(self, key):
                    events.append(('options.get', key))
                    if failure == 'getitem':
                        raise ValueError('foreign keyword value refused')
                    return 'r11'
            class Layout:
                def __bool__(self):
                    events.append(('block-order.truth',))
                    if failure == 'truth':
                        raise KeyboardInterrupt('foreign layout truth')
                    return False
            class Buffers:
                def __iter__(self):
                    events.append(('buffer-exports.iter',))
                    if failure == 'exports':
                        raise SystemExit('foreign exports iterator')
                    return iter([('f0', 'bytes')])
            def later(**kwargs):
                events.append(('later-Code', tuple(kwargs.items())))
                return {'chosen': 'later', 'kwargs': kwargs}
            def first(**kwargs):
                events.append(('first-Code', tuple(kwargs.items())))
                return {'chosen': 'first', 'kwargs': kwargs}
            def options(observed):
                events.append(('code-options', observed is plan))
                backend.Code = later
                return Options()
            arguments = (receiver, document, allowed, Layout(), Buffers(), plan)
            with patch.object(backend, 'Code', first), patch.object(hia_machine_plan, 'code_options', options):
                result = (recorded(self.owner.invoke, '_Emitter.__init__', arguments) if native
                          else recorded(backend._Emitter.__init__, *arguments))
            state = {name: ('document' if value is document else 'allowed' if value is allowed
                           else 'plan' if value is plan else value)
                     for name, value in vars(receiver).items()}
            return result, events, state
        for failure in ('none', 'keys', 'getitem', 'truth', 'exports'):
            with self.subTest(failure=failure):
                self.assertEqual(observation(True, failure), observation(False, failure))

    def test_Emitter_layout_labels_and_foreign_byte_wrapper_keep_observation_order(self):
        from hepta import hia_native_byte_abi
        def ordered(native, missing):
            events = []
            receiver = types.SimpleNamespace()
            class Layout:
                def __getattribute__(self, name):
                    if name == 'get':
                        events.append(('bind-layout.get',))
                    return object.__getattribute__(self, name)
                def get(self, name):
                    events.append(('original-layout.get', name))
                    return ['absent'] if missing else ['b1', 'b0']
            class Function(dict):
                def __getitem__(self, key):
                    events.append(('function.get', key))
                    if key == 'name':
                        receiver.block_order = {'f0': ['wrong-later-layout']}
                    return super().__getitem__(key)
            receiver.block_order = Layout()
            fn = Function(name='f0', blocks=[{'id': 'b0'}, {'id': 'b1'}])
            result = (recorded(self.owner.invoke, '_Emitter.ordered_blocks', (receiver, fn))
                      if native else recorded(backend._Emitter.ordered_blocks, receiver, fn))
            return result, events
        for missing in (False, True):
            self.assertEqual(ordered(True, missing), ordered(False, missing))
        def label(native):
            events = []
            class Serial:
                def __iadd__(self, amount):
                    events.append(('serial.iadd', amount))
                    return 9
            class Prefix(str):
                def __add__(self, other):
                    events.append(('prefix.add', other))
                    return super().__add__(other)
            receiver = types.SimpleNamespace(serial=Serial())
            arguments = (receiver, Prefix('block'))
            result = (recorded(self.owner.invoke, '_Emitter.label', arguments)
                      if native else recorded(backend._Emitter.label, *arguments))
            return result, events, receiver.serial
        self.assertEqual(label(True), label(False))
        def symbol(native):
            events = []
            class Indices:
                def __getitem__(self, name):
                    events.append(('indices.get', name))
                    return 17
            receiver = types.SimpleNamespace(indices=Indices())
            result = (recorded(self.owner.invoke, '_Emitter.function_symbol', (receiver, 'f0'))
                      if native else recorded(backend._Emitter.function_symbol, receiver, 'f0'))
            return result, events
        self.assertEqual(symbol(True), symbol(False))
        def wrapper(native, exception):
            events = []
            class Mapping:
                def __init__(self, ordinal):
                    self.ordinal = ordinal
                def __contains__(self, name):
                    events.append(('buffer.contains', self.ordinal, name))
                    return True
                def __getitem__(self, name):
                    events.append(('buffer.get', self.ordinal, name))
                    return 'second-mapping-value'
            class Receiver:
                reads = 0
                @property
                def foreign_buffer_exports(self):
                    self.reads += 1
                    events.append(('buffer-exports.read', self.reads))
                    return Mapping(self.reads)
            receiver, fn = Receiver(), {'name': 'f0'}
            def leaf(actual_receiver, actual_fn, value):
                events.append(('byte-wrapper', actual_receiver is receiver, actual_fn is fn, value))
                if exception is not None:
                    raise exception('foreign byte wrapper')
            with patch.object(hia_native_byte_abi, 'emit_wrapper', leaf):
                result = (recorded(self.owner.invoke, '_Emitter.wrapper', (receiver, fn))
                          if native else recorded(backend._Emitter.wrapper, receiver, fn))
            return result, events
        for exception in (None, TypeError, KeyboardInterrupt):
            self.assertEqual(wrapper(True, exception), wrapper(False, exception))

    def test_Emitter_lazy_generators_preserve_suspension_errors_and_one_use_resume(self):
        def outcome(function, *arguments):
            try:
                return {'value': function(*arguments)}
            except BaseException as error:
                cause = error.__cause__
                return {'exception': type(error).__name__, 'args': error.args,
                        'cause': None if cause is None else (type(cause).__name__, cause.args)}
        def observation(native, mode, actions, body_exception=None):
            events = []
            class Row:
                def __init__(self, value):
                    self.value = value
                def __getitem__(self, key):
                    active = sys.exception()
                    events.append(('item', self.value, key,
                        None if active is None else (type(active).__name__, active.args)))
                    if body_exception is not None:
                        raise body_exception('foreign generator item')
                    return self.value
            class Source:
                def __init__(self):
                    self.at = 0
                def __iter__(self):
                    events.append(('outer.iter',))
                    return self
                def __next__(self):
                    events.append(('outer.next', self.at))
                    if self.at == 2:
                        raise StopIteration
                    value = self.at + 10
                    self.at += 1
                    return Row(value)
            source = Source()
            iterator = self.owner.generator(mode, iter(source)) if native else (p['type'] for p in source)
            before = list(events)
            self.assertEqual(before, [('outer.iter',)])
            results = []
            try:
                raise KeyError('ambient-handled-exception')
            except KeyError:
                for action in actions:
                    if action == 'next':
                        results.append(outcome(next, iterator))
                    elif action == 'send':
                        results.append(outcome(iterator.send, 'ignored-by-generator-body'))
                    elif action == 'throw':
                        results.append(outcome(iterator.throw, ValueError('injected')))
                    elif action == 'stop':
                        results.append(outcome(iterator.throw, StopIteration('injected-stop')))
                    elif action == 'close':
                        results.append(outcome(iterator.close))
                    else:
                        raise AssertionError('unknown test action')
            return before, results, events
        cases = [
            (('next', 'send', 'next', 'next'), None),
            (('next', 'throw', 'next'), None),
            (('throw', 'next'), None),
            (('next', 'stop', 'next'), None),
            (('next', 'close', 'next'), None),
            (('close', 'next'), None),
            (('next', 'next'), StopIteration),
            (('next', 'next'), ValueError),
            (('next', 'next'), KeyboardInterrupt),
        ]
        for mode in ('_native_generator_0', '_native_generator_1'):
            for actions, exception in cases:
                with self.subTest(mode=mode, actions=actions, exception=exception):
                    self.assertEqual(observation(True, mode, actions, exception),
                                     observation(False, mode, actions, exception))
        mode = self.owner.modes['_native_generator_0']['number']
        def suspended():
            session = LoweringSession(self.owner, mode, (iter([{'type': 'u64'}]),))
            self.assertEqual(session.advance(session.initial), 3)
            self.assertEqual(session.yielded, 'u64')
            return session
        for action in ('observe', 'handoff', 'duplicate-resume', 'wrong-sequence'):
            session = suspended()
            if action == 'duplicate-resume':
                packet = session.resume()
                with self.assertRaises(RuntimeError):
                    session.resume()
            elif action == 'wrong-sequence':
                packet = session.resume()
                words = list(FRAME.unpack(packet))
                words[2] += 1
                with self.assertRaises(RuntimeError):
                    session.step(FRAME.pack(*words))
            else:
                with self.assertRaises(RuntimeError):
                    getattr(session, action)()
            for retry in (session.observe, session.resume, session.handoff,
                          lambda: session.step(session.initial)):
                with self.assertRaises(RuntimeError):
                    retry()
        for exception in (KeyboardInterrupt, MemoryError):
            returned = []
            def after_yield(original):
                def entry(*arguments):
                    result = original(*arguments)
                    if result == 3:
                        returned.append(result)
                        raise exception('after actual native yield')
                    return result
                return entry
            session = LoweringSession(self.owner, mode, (iter([{'type': 'u64'}]),))
            with ExitStack() as stack:
                for image in self.owner.images:
                    stack.enter_context(patch.object(image, '_entry', after_yield(image._entry)))
                with self.assertRaises(exception):
                    session.advance(session.initial)
            self.assertEqual(returned, [3])
            for retry in (session.observe, session.resume, session.handoff,
                          lambda: session.step(session.initial)):
                with self.assertRaises(RuntimeError):
                    retry()


INSTALLED_CHILD = r'''
import importlib.abc,inspect,json,os,sys
from pathlib import Path
from hashlib import sha256
sys.path.insert(0,sys.argv[1])
class NoTools(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname=='tools' or fullname.startswith('tools.'):
            raise AssertionError('installed lowering imported authoring tools')
sys.meta_path.insert(0,NoTools())
root=Path(sys.argv[1])
expected=json.loads(Path(sys.argv[3]).read_bytes())
for name,identity in expected['python'].items():
    assert sha256((root/name).read_bytes()).hexdigest()==identity
actual={p.relative_to(root).as_posix() for p in (root/'hepta').rglob('*.py') if '_data' not in p.parts}
assert actual==set(expected['python'])
from hepta.hia_json_preflight_native import _source_resource_path
for name,identity in expected['resources'].items():
    path=_source_resource_path(name)
    assert root in path.parents and sha256(path.read_bytes()).hexdigest()==identity
from hepta import hia_program_native as backend
from hepta.hia_program import verify_program
from hepta.hia_core_lowering_selection import SELECTOR,ABI_SOURCE,installed_core_lowering,active_core_lowering
from hepta.hia_core_lowering_native import LoweringSession
entries=[]
real=LoweringSession.step
def step(session,packet):
    value=real(session,packet);entries.append(value);return value
LoweringSession.step=step
def forbidden(*args,**kwargs):
    raise AssertionError('retained Function control entered installed child')
for cls in (backend._Function,backend._Emitter):
    for name,method in tuple(cls.__dict__.items()):
        if inspect.isfunction(method) and name!='__new__':
            setattr(cls,name,forbidden)
for name in ('_reject','_words','_bounds','_normalize','_prologue'):
    legacy='_reference'+name
    original=getattr(backend,legacy)
    def guard(*args,_old=original,**kwargs):
        if active_core_lowering() is not None: return forbidden()
        return _old(*args,**kwargs)
    setattr(backend,legacy,guard)
os.environ[SELECTOR]=sys.argv[2]
owner=installed_core_lowering(sys.argv[2],vars(backend))
machine=backend.emit_program_machine(verify_program(expected['document']))
assert machine.object_bytes.startswith(b'\x7fELF')
assert entries and 0 in entries and 1 in entries and 2 in entries
abi=_source_resource_path(ABI_SOURCE)
raw=abi.read_bytes()
abi.write_bytes(raw+b'\n')
try:installed_core_lowering(sys.argv[2],vars(backend))
except ValueError:pass
else:raise AssertionError('warm ABI source change was ignored')
abi.write_bytes(raw);abi.unlink()
try:installed_core_lowering(sys.argv[2],vars(backend))
except FileNotFoundError:pass
else:raise AssertionError('missing installed ABI fell back to checkout')
abi.write_bytes(raw)
assert sys.flags.isolated and sys.flags.no_site and os.environ['PATH']==''
print(json.dumps({'status':'INSTALLED_CORE_LOWERING_PASS','units':len(owner._admitted_bundle.images),
 'source_sha256':dict(owner._admitted_bundle.source_hashes),'abi_sha256':owner._admitted_bundle.abi_sha256,
 'image_sha256':[im.image_sha256 for im in owner._admitted_bundle.images],
 'object_sha256':machine.sha256,'python_files':len(expected['python']),
 'resource_files':len(expected['resources']),'actual_native_steps':len(entries),
 'retained_lowering_forbidden':True,'authoring_forbidden':True,'isolated_without_site':True,'empty_PATH':True}))
'''


if __name__ == '__main__':
    unittest.main()
