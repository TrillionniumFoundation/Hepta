"""Independent ordinary Core/UNPACK composition controls.

The original Core component15 + machine51 + Core50 remain a separate complete
116-method gate. These eight methods supplement it, without inheriting its
qualification result or treating the CPython transaction as a HIA object VM.
"""
from __future__ import annotations
import ast
from contextlib import ExitStack
from dataclasses import fields
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hepta import hia_program_native as backend
from hepta import hia_core_lowering_native as outer
from hepta import hia_core_lowering_selection as core
from hepta import hia_core_unpack_native as primitive
from hepta import hia_core_unpack_selection as selection
from hepta.hia_program import verify_program
from tests.test_hia_program_native import minimal_document

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = 'HEPTA_HIA_CORE_UNPACK_FIXTURE_EVIDENCE'


def observed(call):
    try:
        return ('value', call())
    except BaseException as error:
        return ('error', type(error), error.args)


def metadata(machine):
    return {item.name: getattr(machine, item.name) for item in fields(machine)
            if item.name != 'implementation_sha256'}


def forbidden(*args, **kwargs):
    raise AssertionError('retained complete Python UNPACK was entered')


class UnpackCompositionSourceTests(unittest.TestCase):
    def test_original_39_units_and_Core_ABI_are_unchanged(self):
        path = ROOT / 'tests/fixtures/hia_core_unpack_core39.json'
        expected = json.loads(path.read_bytes())
        self.assertEqual(expected['base_commit'], 'd0e110e19f9433baaf202a0f605671c7205b4cff')
        self.assertEqual(len(expected['files']), 40)
        abi = core.checked_abi((ROOT / core.ABI_SOURCE).read_bytes())
        self.assertEqual(len(abi['units']), 38)
        self.assertEqual(len(abi['modes']), 36)
        self.assertEqual(set(expected['files']), {core.ABI_SOURCE, *core.source_names(abi)})
        for name, pin in expected['files'].items():
            raw = (ROOT / name).read_bytes()
            self.assertEqual((len(raw), sha256(raw).hexdigest()), (pin['size'], pin['sha256']), name)

    def test_retained_UNPACK_and_strict_cold_admission_remain_independent(self):
        old = ast.parse((ROOT / 'tests/fixtures/hia_core_lowering_native_before_unpack.py.txt').read_bytes())
        cls = next(n for n in old.body if isinstance(n, ast.ClassDef) and n.name == 'LoweringSession')
        method = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == '_primitive')
        branch = next(n for n in method.body if isinstance(n, ast.If)
                      and ast.dump(n.test) == ast.dump(ast.parse('opcode == 14', mode='eval').body))
        current = ast.parse((ROOT / 'hepta/hia_core_lowering_native.py').read_bytes())
        helper = next(n for n in current.body if isinstance(n, ast.FunctionDef) and n.name == '_host_unpack')
        # Two original operand observations remain at the outer boundary.
        self.assertEqual(ast.dump(ast.Module(body=branch.body[2:], type_ignores=[])),
                         ast.dump(ast.Module(body=helper.body, type_ignores=[])))
        from tools.build_hia_core_unpack import build
        with tempfile.TemporaryDirectory(prefix='unpack-cold-refusal-') as temporary:
            directory = Path(temporary)
            compiler, cold, output = directory / 'compiler', directory / 'cold.json', directory / 'output'
            compiler.write_bytes(b'unqualified')
            cold.write_text('{}')
            with self.assertRaises((ValueError, KeyError, TypeError)):
                build(output, compiler, cold)
            self.assertFalse(output.exists())
        raw = selection.current_inputs()[selection.ABI_SOURCE]
        for key in ('input_bytes', 'output_bytes', 'workspace_bytes', 'arity_minimum'):
            changed = json.loads(raw)
            changed[key] = True
            with self.assertRaises(ValueError):
                selection.checked_abi(json.dumps(changed).encode())


class UnpackCompositionNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        core_path = os.environ.get('HEPTA_HIA_CORE_LOWERING_DEVELOPMENT_MANIFEST') or os.environ.get(core.SELECTOR)
        unpack_path = os.environ.get(selection.SELECTOR)
        if not core_path or not unpack_path:
            raise unittest.SkipTest('requires explicit paired Core and UNPACK manifests')
        cls.core_manifest = Path(core_path).resolve(strict=True)
        cls.unpack_manifest = Path(unpack_path).resolve(strict=True)
        evidence = os.environ.get(EVIDENCE)
        if evidence:
            cls.folder = Path(evidence).resolve()
            cls.folder.mkdir(parents=True, exist_ok=False)
        else:
            temporary = tempfile.TemporaryDirectory(prefix='unpack-composition-')
            cls.addClassCleanup(temporary.cleanup)
            cls.folder = Path(temporary.name)
        cls.owner = core.installed_core_lowering(cls.core_manifest, vars(backend))
        if cls.owner.unpack is None:
            raise AssertionError('paired explicit Core admission lost the UNPACK owner')
        cls.companion = cls.owner.unpack
        cls.before_inputs = selection.current_inputs()
        cls.before_manifest = cls.unpack_manifest.read_bytes()
        cls.before_image = (cls.unpack_manifest.parent / 'core-unpack.image.bin').read_bytes()

    @classmethod
    def tearDownClass(cls):
        if (selection.current_inputs() != cls.before_inputs
                or cls.unpack_manifest.read_bytes() != cls.before_manifest
                or (cls.unpack_manifest.parent / 'core-unpack.image.bin').read_bytes() != cls.before_image):
            raise AssertionError('UNPACK composition inputs changed')

    def selected(self):
        return patch.dict(os.environ, {core.SELECTOR: str(self.core_manifest),
                                      selection.SELECTOR: str(self.unpack_manifest)})

    def emitter(self, value):
        class Code:
            data = b''
            def finalize(self):
                return value
        return SimpleNamespace(document={'schema': minimal_document()['schema'],
                               'functions': [], 'exports': ['f']}, machine_plan=None,
                               exports=['f'], c=Code(), symbols=[], function_alignment=16)

    def at_unpack(self, value):
        receiver = self.emitter(value)
        mode = self.owner.modes['_Emitter.render']['number']
        session = outer.LoweringSession(self.owner, mode, (receiver,))
        packet = session.initial
        while True:
            status = session.step(packet)
            if status == 1 and session.request[0][2] == 14:
                return session
            self.assertIn(status, (1, 2))
            packet = session.handoff() if status == 2 else session.observe()

    def test_ordinary_machine_uses_HIA_unpack_with_old_policy_poisoned(self):
        from tools.qualify_hia_program import qualification_program
        from tests.test_hia_program_native_review import _empty_memory_program
        documents = [minimal_document(), _empty_memory_program(), qualification_program()]
        with patch.dict(os.environ, {core.SELECTOR: ''}):
            expected = [backend.emit_program_machine(verify_program(doc)) for doc in documents]
        returns = []
        step = primitive.UnpackSession._step
        def record(session, packet):
            result = step(session, packet)
            returns.append((session.image.image_sha256, result))
            return result
        with self.selected(), patch.object(outer, '_host_unpack', forbidden), \
                patch.object(primitive.UnpackSession, '_step', record):
            for document, wanted in zip(documents, expected):
                actual = backend.emit_program_machine(verify_program(document))
                self.assertEqual(metadata(actual), metadata(wanted))
                self.assertNotEqual(actual.implementation_sha256, wanted.implementation_sha256)
        self.assertTrue(returns)
        self.assertEqual({identity for identity, status in returns}, {self.companion.image.image_sha256})
        self.assertTrue({0, 1} <= {status for identity, status in returns})

    def test_actual_outer_request_is_once_consumed_before_foreign_iteration(self):
        for size in range(5):
            for ambient in (False, True):
                with self.subTest(size=size, ambient=ambient):
                    def run(native):
                        events = []
                        values = [b'\xc3', [], object(), object()][:size]
                        class Iterable:
                            def __iter__(self):
                                events.append(('iter', type(sys.exception())))
                                return Iterator()
                        class Iterator:
                            index = 0
                            def __next__(self):
                                index = self.index
                                events.append(('next', index, type(sys.exception())))
                                self.index += 1
                                if index >= len(values):
                                    raise StopIteration
                                return values[index]
                        receiver = self.emitter(Iterable())
                        def call():
                            return self.owner.invoke('_Emitter.render', (receiver,)) if native else backend._Emitter.render(receiver)
                        if ambient:
                            try:
                                raise LookupError('ambient')
                            except LookupError:
                                result = observed(call)
                        else:
                            result = observed(call)
                        return result, events
                    with patch.object(outer, '_host_unpack', forbidden):
                        native = run(True)
                    self.assertEqual(native, run(False))
                    self.assertEqual([item[1] for item in native[1] if item[0] == 'next'],
                                     list(range(min(size + 1, 3))))
        events, active = [], []
        class Reentrant:
            def __iter__(self):
                events.append('iter')
                for _ in range(2):
                    try:
                        active[0].observe()
                    except RuntimeError:
                        events.append('closed')
                    else:
                        raise AssertionError('outer effect was replayed')
                return iter((b'\xc3', []))
        session = self.at_unpack(Reentrant())
        active.append(session)
        with patch.object(outer, '_host_unpack', forbidden):
            packet = session.observe()
        self.assertEqual(events, ['iter', 'closed', 'closed'])
        self.assertTrue(session.finished)
        for retry in (session.observe, session.handoff, lambda: session.step(packet)):
            with self.assertRaises(RuntimeError):
                retry()
        self.assertEqual(events, ['iter', 'closed', 'closed'])

    def test_scope_captures_companion_and_absence_across_environment_changes(self):
        document = verify_program(minimal_document())
        with self.selected(), core.native_core_lowering_scope(vars(backend)):
            owner = core.active_core_lowering()
            self.assertIs(owner.unpack, self.companion)
            identity = core.native_implementation_identity(vars(backend))
            with patch.dict(os.environ, {core.SELECTOR: '/missing-core', selection.SELECTOR: '/missing-unpack'}), \
                    patch.object(outer, '_host_unpack', forbidden):
                self.assertIs(core.selected_core_lowering(vars(backend)), owner)
                self.assertEqual(core.native_implementation_identity(vars(backend)), identity)
                backend.emit_program_machine(document)
        with self.selected(), patch.dict(os.environ, {selection.SELECTOR: ''}), \
                core.native_core_lowering_scope(vars(backend)):
            owner = core.active_core_lowering()
            self.assertIsNone(owner.unpack)
            calls = []
            original = outer._host_unpack
            def recorded(value, count):
                calls.append(count)
                return original(value, count)
            with patch.dict(os.environ, {selection.SELECTOR: str(self.unpack_manifest)}), \
                    patch.object(outer, '_host_unpack', recorded):
                backend.emit_program_machine(document)
                self.assertIs(core.selected_core_lowering(vars(backend)), owner)
            self.assertTrue(calls)

    def test_fresh_manifest_compiler_and_warm_sources_refuse_without_fallback(self):
        with self.selected(), patch.object(outer, '_host_unpack', forbidden):
            with patch.dict(os.environ, {selection.SELECTOR: str(self.folder / 'missing.json')}):
                with self.assertRaises(FileNotFoundError):
                    core.installed_core_lowering(self.core_manifest, vars(backend))
            for relative in selection.current_inputs():
                changed = selection.current_inputs()
                changed[relative] += b'\n'
                with patch.object(selection, 'current_inputs', return_value=changed):
                    with self.assertRaises(ValueError):
                        core.installed_core_lowering(self.core_manifest, vars(backend))
            folder = self.folder / 'invalid-manifests'
            folder.mkdir()
            value = json.loads(self.before_manifest)
            value['compiler_sha256'] = 'f' * 64
            path = folder / 'manifest.json'
            path.write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                selection.installed_unpack(path, self.companion._admitted_unpack.compiler_sha256)
            value = json.loads(self.before_manifest)
            path.write_text(json.dumps(value) + '\n\n')
            (folder / 'core-unpack.image.bin').write_bytes(self.before_image[:-1] + bytes([self.before_image[-1] ^ 1]))
            with self.assertRaises(ValueError):
                selection.installed_unpack(path, self.companion._admitted_unpack.compiler_sha256)

    def test_all_companion_inputs_and_transaction_are_bound_after_selection(self):
        identity = selection.implementation_identity(self.companion)
        for relative in selection.current_inputs():
            changed = selection.current_inputs()
            changed[relative] += b'\n'
            with patch.object(selection, 'current_inputs', return_value=changed):
                with self.assertRaises(ValueError):
                    selection.implementation_identity(self.companion)
        with patch.object(primitive, 'SHIM_SHA256', 'f' * 64):
            with self.assertRaises(ValueError):
                selection.implementation_identity(self.companion)
        self.assertEqual(selection.implementation_identity(self.companion), identity)
        with self.selected(), core.native_core_lowering_scope(vars(backend)):
            self.assertIn(identity, core.native_implementation_identity(vars(backend)))

    def test_after_actual_UNPACK_return_failure_permanently_closes_outer(self):
        for exception in (KeyboardInterrupt, MemoryError):
            with self.subTest(exception=exception):
                session = self.at_unpack((b'\xc3', []))
                actual, inner = [], []
                step = primitive.UnpackSession._step
                def after_return(candidate, packet):
                    result = step(candidate, packet)
                    if result == 0:
                        actual.append(result)
                        inner.append(candidate)
                        raise exception('after actual UNPACK return')
                    return result
                with patch.object(outer, '_host_unpack', forbidden), \
                        patch.object(primitive.UnpackSession, '_step', after_return):
                    with self.assertRaises(exception):
                        session.observe()
                self.assertEqual(actual, [0])
                self.assertTrue(session.finished)
                self.assertTrue(inner[0].finished)
                self.assertFalse(any(inner[0].cells[2:]))
                self.assertIsNone(inner[0].returned)
                for retry in (session.observe, session.handoff, lambda: session.step(session.initial)):
                    with self.assertRaises(RuntimeError):
                        retry()
        errors = []
        with patch.object(sys, 'unraisablehook', errors.append):
            with self.assertRaises(TypeError):
                primitive.UnpackSession(None, None, (), True)
        self.assertEqual(errors, [])


if __name__ == '__main__':
    unittest.main()
