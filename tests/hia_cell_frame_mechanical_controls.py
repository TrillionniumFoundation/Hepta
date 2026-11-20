"""Mechanical controls only; no adjustment of any original observer or GC count."""
from pathlib import Path
import gc
from hashlib import sha256
import importlib.util
import json
import sys
import sysconfig
import types
import unittest
import weakref

if len(sys.argv) != 3:
    raise SystemExit('usage: hia_cell_frame_mechanical_controls.py SOURCE OUTPUT')
ROOT = Path(sys.argv[1]).resolve(strict=True)
HERE = Path(sys.argv[2]).resolve()
if HERE.is_relative_to(ROOT):
    raise ValueError('mechanical observations must be outside the source tree')
HERE.mkdir(mode=0o700)
sys.path.insert(0, str(ROOT))
from hepta import _hia_cell_frame as carrier
from hepta import hia_service_verification_native as native

LIBRARY = ROOT / 'hepta' / ('_hia_cell_frame' + sysconfig.get_config_var('EXT_SUFFIX'))


def empty():
    return types.CellType()


def bindings(names, cells):
    return carrier.CellBindings(names, cells, native._read_empty_free_cell)


class MechanicalCellFrameTests(unittest.TestCase):
    def test_actual_cells_rebinding_deletion_and_real_empty_error(self):
        cell = types.CellType(object())
        owner = bindings(('marker',), (cell,))
        self.assertIs(owner['marker'], cell.cell_contents)
        replacement = object()
        cell.cell_contents = replacement
        self.assertIs(owner['marker'], replacement)
        for outer in (False, True):
            from tests.hia_service_verification_cells import _fields
            del cell.cell_contents
            def compare(active):
                observed = []
                for action in (lambda: native._read_empty_free_cell('marker', cell),
                               lambda: owner['marker']):
                    try:
                        action()
                    except NameError as error:
                        observed.append(_fields(error, active))
                    else:
                        self.fail('empty cell did not raise actual NameError')
                self.assertEqual(observed[0], observed[1])
            if outer:
                try:
                    raise KeyError('active caller')
                except KeyError as active:
                    compare(active)
            else:
                compare(None)
            cell.cell_contents = replacement
        self.assertIs(owner['marker'], replacement)

    def test_subset_keeps_same_cell_after_parent_release(self):
        first, second = types.CellType('first'), types.CellType('second')
        owner = bindings(('first', 'second'), (first, second))
        selected = owner.subset('second')
        reference = weakref.ref(owner)
        del owner
        self.assertIsNone(reference())
        self.assertIs(selected['second'], second.cell_contents)
        second.cell_contents = object()
        self.assertIs(selected['second'], second.cell_contents)
        with self.assertRaises(KeyError):
            selected['first']
        del second.cell_contents
        with self.assertRaises(NameError):
            selected['second']

    def test_frame_receives_original_objects_and_current_namespaces(self):
        namespace, captured, imports = {}, {}, {}
        image, result, name = object(), object(), object()
        cell = types.CellType('initial')
        owner = bindings(('marker',), (cell,))
        events = []
        class Frame:
            def __init__(self, actual_image, mode, bound, **kwargs):
                self.bound = bound
                events.append((actual_image is image, mode, bound['name'] is name,
                    bound['cells'] is owner, kwargs['namespace'] is namespace,
                    kwargs['global_builtins'] is captured, kwargs['import_capsules'] is imports))
                namespace['actual'] = object()
            def finish(self):
                events.append(owner['marker'] is cell.cell_contents)
                return result
        callback = carrier.FrameCallback(Frame, image, 10, owner, namespace, captured, imports)
        for call in (lambda: callback(name), lambda: callback(name=name)):
            self.assertIs(call(), result)
        self.assertEqual(events, [(True, 10, True, True, True, True, True), True] * 2)
        for call in (lambda: callback(), lambda: callback(name, name),
                     lambda: callback(name, name=name), lambda: callback(unknown=name)):
            with self.assertRaises(TypeError):
                call()

    def test_recursive_cell_rebinding_and_exception_identity(self):
        cell = empty()
        owner = bindings(('acyclic',), (cell,))
        namespace, captured, imports = {}, {}, {}
        marker = RuntimeError('actual finish failure')
        calls = []
        class Frame:
            def __init__(self, image, mode, bound, **kwargs):
                self.bound = bound
            def finish(self):
                if self.bound['name'] == 'outer':
                    return self.bound['cells']['acyclic']('inner')
                if self.bound['name'] == 'error':
                    raise marker
                calls.append(self.bound['name'])
                return self.bound['name']
        callback = carrier.FrameCallback(Frame, object(), 10, owner,
                                          namespace, captured, imports)
        cell.cell_contents = callback
        self.assertEqual(callback('outer'), 'inner')
        self.assertEqual(calls, ['inner'])
        cell.cell_contents = lambda name: ('replacement', name)
        self.assertEqual(callback('outer'), ('replacement', 'inner'))
        try:
            callback('error')
        except RuntimeError as error:
            self.assertIs(error, marker)
        else:
            self.fail('actual finish failure was lost')
        del cell.cell_contents
        with self.assertRaises(NameError):
            callback('outer')

    def test_owned_python_references_and_heap_type_module_cycles_are_visible(self):
        def make_cycle():
            selected = importlib.util.spec_from_file_location('_hia_cell_frame', LIBRARY)
            module = importlib.util.module_from_spec(selected)
            selected.loader.exec_module(module)
            cell = empty()
            owner = module.CellBindings(('acyclic',), (cell,), native._read_empty_free_cell)
            image = types.SimpleNamespace(value='owned')
            namespace, captured, imports = {}, {}, {}
            callback = module.FrameCallback(lambda *a, **kw: None, image, 10,
                                             owner, namespace, captured, imports)
            cell.cell_contents = callback
            module.owner = owner
            module.callback = callback
            for value in (owner, callback):
                self.assertTrue(gc.is_tracked(value))
                self.assertIn(type(value), gc.get_referents(value))
            self.assertIn(cell, gc.get_referents(owner))
            actual = gc.get_referents(callback)
            for value in (owner, image, namespace, captured, imports):
                self.assertTrue(any(value is ref for ref in actual))
            return [weakref.ref(module), weakref.ref(module.CellBindings),
                    weakref.ref(module.FrameCallback), weakref.ref(owner), weakref.ref(callback)]
        refs = make_cycle()
        self.assertTrue(all(ref() is not None for ref in refs))
        gc.collect()
        self.assertTrue(all(ref() is None for ref in refs))

    def test_invalid_mechanical_inputs_and_module_attribute_rebinding(self):
        for args in (([], (), lambda *a: None), (('x',), (object(),), lambda *a: None),
                     (('x',), (empty(),), None)):
            with self.assertRaises(TypeError):
                carrier.CellBindings(*args)
        for args in (((), (), lambda *a: None),
                     (('x', 'x'), (empty(), empty()), lambda *a: None)):
            with self.assertRaises(ValueError):
                carrier.CellBindings(*args)
        owner = bindings(('x',), (empty(),))
        actual = carrier.CellBindings
        try:
            carrier.CellBindings = object
            callback = carrier.FrameCallback(lambda *a, **kw: None,
                                               object(), 10, owner, {}, {}, {})
            self.assertIs(type(callback), carrier.FrameCallback)
            with self.assertRaises(TypeError):
                carrier.FrameCallback(lambda *a, **kw: None, object(), 10, object(), {}, {}, {})
        finally:
            carrier.CellBindings = actual
        with self.assertRaises(KeyError):
            owner.subset('absent')


if __name__ == '__main__':
    watched = (LIBRARY, ROOT / 'hepta/native/cell_frame.c',
               ROOT / 'hepta/hia_service_verification_native.py')
    before = {str(path): sha256(path.read_bytes()).hexdigest() for path in watched}
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(MechanicalCellFrameTests))
    after = {str(path): sha256(path.read_bytes()).hexdigest() for path in watched}
    report = {'schema': 'hepta.development.cell-frame-mechanical.v1',
              'status': 'PASS' if result.wasSuccessful() and before == after else 'FAIL',
              'tests': result.testsRun, 'skips': len(result.skipped),
              'runtime': sys.version, 'before': before, 'after': after,
              'original_185_or_native_or_installed_qualification': False}
    (HERE / 'mechanical-r1.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    raise SystemExit(0 if report['status'] == 'PASS' else 1)
