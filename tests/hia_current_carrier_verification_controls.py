"""Actual current Verification graph through the HIA-owned Cell carrier.

This development control uses a minimal parent-cell fixture but invokes the
unmodified real ServiceVerificationFrame constructor, HIA graph and finish.
Original mechanical controls remain separate and unchanged.
"""
from pathlib import Path
from hashlib import sha256
from contextlib import contextmanager
import argparse
import gc
import json
import sys
import types
import unittest
import weakref


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--captured-current', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = args.captured_current.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(mode=0o700)
    def inventory():
        result = {}
        for path in sorted(root.rglob('*')):
            if path.is_file():
                assert not path.is_symlink()
                raw = path.read_bytes()
                result[path.relative_to(root).as_posix()] = {
                    'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
                    'mode': path.stat().st_mode & 0o777}
        return result
    before = inventory()
    sys.path.insert(0, str(root / 'source'))
    from hepta import hia_native_helpers as authority
    from hepta import hia_cell_frame as cell_loader
    from hepta import hia_service_verification_native as verification
    from hepta import hia_agent_service as service
    manifest = root / 'components/verification/manifest.json'
    current = root / 'current-carriers.json'
    original = root / 'typed-page.json'
    current_raw, original_raw = current.read_bytes(), original.read_bytes()
    observations = []
    @contextmanager
    def selected(native):
        path, raw = (current, current_raw) if native else (original, original_raw)
        with authority.native_helpers_scope(str(path), sha256(raw).hexdigest()) as binding:
            yield binding
            binding.check()
    def parent(image, blocks):
        # Only the four captured parent locals are prepared here. The callback
        # creates every child as a complete actual production frame.
        value = verification.ServiceVerificationFrame.__new__(verification.ServiceVerificationFrame)
        value.image = image
        value.namespace = service._SERVICE_VERIFICATION_NAMESPACE
        mode = verification.PRIVATE_ORIGINS[verification.ACYCLIC]
        value.global_builtins = service._SERVICE_VERIFICATION_GLOBAL_BUILTINS[mode]
        value.import_capsules = service._SERVICE_VERIFICATION_IMPORTS
        names = ('blocks', 'visiting', 'done', 'acyclic')
        value.data = verification._LocalStorage(names, frozenset(names))
        value.data['blocks'], value.data['visiting'], value.data['done'] = blocks, set(), set()
        callback = value._make_acyclic()
        value.data['acyclic'] = callback
        return value, callback
    def details(error, active):
        return {'type': type(error).__name__, 'args': error.args,
                'name': getattr(error, 'name', None),
                'cause': error.__cause__ is None,
                'context_is_active': error.__context__ is active,
                'suppress_context': error.__suppress_context__}

    class ActualVerificationCell(unittest.TestCase):
        def test_actual_graph_branch_cycle_and_repeated_done(self):
            graphs = (
                ('leaf', {'a': {'term': {'op': 'return'}}}, True),
                ('chain', {'a': {'term': {'op': 'jump', 'target': 'b'}},
                           'b': {'term': {'op': 'return'}}}, True),
                ('branch', {'a': {'term': {'op': 'branch', 'then': {'target': 'b'}, 'else': {'target': 'c'}}},
                            'b': {'term': {'op': 'return'}}, 'c': {'term': {'op': 'return'}}}, True),
                ('cycle', {'a': {'term': {'op': 'jump', 'target': 'b'}},
                           'b': {'term': {'op': 'jump', 'target': 'a'}}}, False))
            for name, graph, expected in graphs:
                values = []
                for native in (False, True):
                    with selected(native):
                        image = verification.installed_service_verification(str(manifest))
                        owner, callback = parent(image, graph)
                        carrier = cell_loader.selected_extension()
                        if native:
                            self.assertIs(type(callback), carrier.FrameCallback)
                            start = carrier._policy_observation()
                        else:
                            self.assertIs(type(callback), types.MethodType)
                        result = callback('a')
                        self.assertIs(result, expected)
                        second = callback(name='a')
                        self.assertIs(second, expected)
                        values.append((result, second, tuple(sorted(owner.data['visiting'])),
                                       tuple(sorted(owner.data['done']))))
                        if native:
                            end = carrier._policy_observation()
                            self.assertGreater(end['native_calls'], start['native_calls'])
                            self.assertGreater(end['invocations'], start['invocations'])
                            self.assertEqual(end['protocol_failures'], start['protocol_failures'])
                            observations.append({'id': name, 'before': start, 'after': end})
                self.assertEqual(values[0], values[1])

        def test_actual_graph_late_recursive_cell_and_exception_identity(self):
            graph = {'a': {'term': {'op': 'jump', 'target': 'b'}},
                     'b': {'term': {'op': 'return'}}}
            results = []
            for native in (False, True):
                with selected(native):
                    image = verification.installed_service_verification(str(manifest))
                    owner, callback = parent(image, graph)
                    calls = []
                    def replacement(name):
                        calls.append(name)
                        return False
                    owner.data['acyclic'] = replacement
                    self.assertIs(callback('a'), False)
                    self.assertEqual(calls, ['b'])
                    marker = RuntimeError('actual current recursive effect')
                    def rejected(name):
                        raise marker
                    owner.data['visiting'].clear()
                    owner.data['acyclic'] = rejected
                    try:
                        callback('a')
                    except RuntimeError as error:
                        self.assertIs(error, marker)
                    else:
                        self.fail('real graph lost the original effect exception')
                    fields = []
                    for active_handler in (False, True):
                        owner.data['visiting'].clear()
                        del dict.__getitem__(owner.data, 'acyclic').cell_contents
                        def capture(active):
                            try:
                                callback('a')
                            except NameError as error:
                                fields.append(details(error, active))
                            else:
                                self.fail('empty original cell did not raise')
                        if active_handler:
                            try:
                                raise KeyError('actual outer handler')
                            except KeyError as active:
                                capture(active)
                        else:
                            capture(None)
                    results.append(fields)
            self.assertEqual(results[0], results[1])
            observations.append({'id': 'late-recursive-and-empty-cell', 'fields': results[1]})

        def test_callback_retains_only_cells_after_parent_release(self):
            for native in (False, True):
                with selected(native):
                    image = verification.installed_service_verification(str(manifest))
                    owner, callback = parent(image, {'a': {'term': {'op': 'return'}}})
                    owner_ref = weakref.ref(owner)
                    recursive = dict.__getitem__(owner.data, 'acyclic')
                    del owner
                    self.assertIsNone(owner_ref())
                    self.assertIs(callback('a'), True)
                    del recursive.cell_contents
                    if native:
                        self.assertTrue(gc.is_tracked(callback))
                        callback_ref = weakref.ref(callback)
                        del callback
                        gc.collect()
                        self.assertIsNone(callback_ref())
            observations.append({'id': 'actual-parent-release-and-native-callback-gc', 'passed': True})

    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(ActualVerificationCell))
    after = inventory()
    stable = before == after
    report = {'schema': 'hepta.hia.current-carrier-verification-controls.v1',
              'scope': 'ACTUAL_CURRENT_HIA_GRAPH_WITH_CAPTURED_PARENT_CELLS',
              'passed': result.wasSuccessful() and stable, 'tests': result.testsRun,
              'skipped': len(result.skipped), 'observations': observations,
              'source_and_products_unchanged': stable, 'before': before, 'after': after,
              'default_release_or_installed_qualification_claimed': False}
    (output / 'report.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('passed', 'tests', 'skipped', 'source_and_products_unchanged')}))
    return 0 if report['passed'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
