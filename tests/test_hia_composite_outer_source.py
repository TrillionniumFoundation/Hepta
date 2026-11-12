"""Outer source reproduction, retained oracle custody and cold-build admission."""
from hashlib import sha256
import ctypes
import gc
import inspect
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import weakref

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_composite_outer_native import SOURCES, NativeCompositeOuter
from hepta.hia_composite_outer_native import NativeOuterInvocation, OBJECTS
from hepta.hia_composite_constructor_native import NativeConstructorInvocation
from hepta.hia_composite_functions_native import NativeFunctionSession
from hepta.hia_program import HIAProgramRejected
from hepta.hia_program_composite import _Elaborator
from tools.generate_hia_composite_outer import document


class OuterSourceTests(unittest.TestCase):
    def test_both_complete_sources_reproduce_below_original_limits(self):
        for kernel, path in SOURCES.items():
            data = document(kernel)
            with self.subTest(kernel=kernel):
                self.assertEqual(render_assembly(data).encode(), path.read_bytes())
                functions = data['functions']
                blocks = [block for fn in functions for block in fn['blocks']]
                self.assertLessEqual(len(path.read_bytes()), 1 << 20)
                self.assertLessEqual(len(functions), 128)
                self.assertLessEqual(len(blocks), 1536)
                self.assertLessEqual(sum(len(block['ops']) for block in blocks), 8192)
                for fn in functions:
                    self.assertLessEqual(len(fn['params']), 16)
                    self.assertLessEqual(len(fn['blocks']), 256)
                    definitions = {param['name'] for param in fn['params']}
                    for block in fn['blocks']:
                        self.assertLessEqual(len(block['params']), 16)
                        definitions.update(param['name'] for param in block['params'])
                        definitions.update(param['name'] for op in block['ops'] for param in op['out'])
                    self.assertLessEqual(len(definitions), 2048)

    def test_retained_lower_exact_and_bundle_indivisible(self):
        original = inspect.getsource(_Elaborator._reference_lower).replace(
            'def _reference_lower(', 'def lower(', 1)
        self.assertEqual(sha256(original.encode()).hexdigest(),
                         '3f49bdaabc0cd14e01e1d8f0eabb0559306e22cc66d8656cb5eb40ff1facfc89')
        with self.assertRaisesRegex(ValueError, 'every kernel and dependency'):
            NativeCompositeOuter({'owner': object()}, types_source_sha256='0' * 64,
                                 helpers_source_sha256='0' * 64, function_sources_sha256={})

    def test_complete_cold_gate_precedes_any_artifact_write(self):
        from tools.build_hia_composite_outer import build
        with tempfile.TemporaryDirectory(prefix='hia-outer-gate-') as temporary:
            root = Path(temporary)
            compiler, report = root / 'compiler', root / 'cold.json'
            compiler.write_bytes(b'development image')
            report.write_text(json.dumps({'status': 'DEVELOPMENT_ONLY'}))
            for existing in (False, True):
                output = root / ('existing' if existing else 'absent-parent') / 'bundle'
                if existing:
                    output.mkdir(parents=True)
                    (output / 'sentinel').write_bytes(b'preserved')
                before = {path.relative_to(root): path.read_bytes()
                          for path in root.rglob('*') if path.is_file()}
                with self.assertRaisesRegex(ValueError, 'completed matching native cold qualification'):
                    build(output, compiler, report)
                after = {path.relative_to(root): path.read_bytes()
                         for path in root.rglob('*') if path.is_file()}
                self.assertEqual(before, after)
                self.assertEqual(output.exists(), existing)
                if not existing:
                    self.assertFalse(output.parent.exists())

    def test_partial_allocation_failure_releases_owned_buffer_with_held_error(self):
        real_create = ctypes.create_string_buffer
        held = []
        for kind in ('constructor', 'outer'):
            with self.subTest(kind=kind):
                refs, calls = [], []
                types = SimpleNamespace()
                session = NativeFunctionSession.__new__(NativeFunctionSession)
                session.types, session._workspace, session.helpers = types, object(), object()
                owner = SimpleNamespace(_native_function_session=session, native_types=types,
                    signatures={}, document={}, serial=0, value_slots=0, helpers=[], helper_names={})
                def allocated(*args):
                    calls.append(args)
                    if len(calls) == 2:
                        raise MemoryError('injected second-buffer allocation failure')
                    value = real_create(32)
                    refs.append(weakref.ref(value))
                    return value
                try:
                    with patch.object(ctypes, 'create_string_buffer', new=allocated):
                        if kind == 'constructor':
                            NativeConstructorInvocation({}, owner, {})
                        else:
                            NativeOuterInvocation({}, owner)
                except MemoryError as error:
                    held.append(error)
                else:
                    self.fail('allocation failure did not propagate')
                gc.collect()
                self.assertEqual(len(calls), 2)
                self.assertIsNone(refs[0]())
        self.assertEqual(len(held), 2)

    def test_all_poisoned_bridge_entries_refuse_before_native_or_identity_work(self):
        outer = NativeOuterInvocation.__new__(NativeOuterInvocation)
        outer._broken = True
        sentinel = object()
        outer._source_index = {5: sentinel}
        for callback in (lambda: outer._frame(64), lambda: outer._invoke(b''),
                         outer._borrow_function, lambda: outer._borrow_helper(None),
                         outer._next, lambda: outer._bind(OBJECTS, {}, 1),
                         lambda: outer._stream(0)):
            with self.assertRaisesRegex(HIAProgramRejected, 'already refused'):
                callback()
            self.assertEqual(outer._source_index, {5: sentinel})
        constructor = NativeConstructorInvocation.__new__(NativeConstructorInvocation)
        constructor._broken = True
        for callback in (lambda: constructor._frame(64), lambda: constructor._invoke(b''),
                         constructor._run, lambda: constructor._stream(0, 0)):
            with self.assertRaisesRegex(HIAProgramRejected, 'already refused'):
                callback()


if __name__ == '__main__':
    unittest.main()
