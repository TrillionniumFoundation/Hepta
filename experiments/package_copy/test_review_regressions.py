"""Independent adversarial review of the restricted Package copy profile."""
import copy
import inspect
import pathlib
import sys
import subprocess
import unittest
from unittest.mock import patch

from hepta.packages import Package
from experiments.package_copy import owner as subject
from experiments.request_load.context import Rejected


def package():
    p = pathlib.PosixPath('/review/a')
    _ = p.parts
    return Package(p, 'review', '1.0.0', p, 'bin', p)


class PackageReview(unittest.TestCase):
    def observed(self, action):
        events, depth = [], 0
        code = subject._COPY.__code__
        previous = sys.getprofile()
        def profile(frame, event, argument):
            nonlocal depth
            if frame.f_code is code:
                if event == 'call':
                    depth += 1
                    events.append((type(frame.f_locals['x']), depth))
                elif event == 'return':
                    depth -= 1
        sys.setprofile(profile)
        try:
            result = action()
        finally:
            sys.setprofile(previous)
        return result, events

    def refuse(self, value, owner=None):
        owner = owner or subject.Owner()
        def action():
            with self.assertRaises(Rejected):
                owner._authority_copy(subject._COPY, value, 'package')
        _, events = self.observed(action)
        self.assertEqual(events, [])
        self.assertTrue(owner.context.closed)

    def test_each_mutable_static_pin_rejects_before_real_copy(self):
        tested = 0
        for namespace, name, original in subject._PINS:
            if name in ('__mro__', '__bases__', '__dict__', '__class__', '__new__'):
                continue
            with self.subTest(namespace=repr(namespace), name=name):
                value, owner = package(), subject.Owner()
                own = vars(namespace).get(name, subject._MISSING)
                try:
                    setattr(namespace, name, object())
                except (TypeError, AttributeError):
                    self.fail('Expected mutable pin: ' + name)
                try:
                    self.refuse(value, owner)
                finally:
                    if own is subject._MISSING:
                        delattr(namespace, name)
                    else:
                        setattr(namespace, name, own)
                tested += 1
        self.assertGreater(tested, 100)

    def test_constructor_pins_in_isolated_processes(self):
        # Changing inherited __new__ can leave CPython tp_new changed even
        # after deleting the temporary class attribute. Do not poison a suite.
        for index, (namespace, name, _) in enumerate(subject._PINS):
            if name != '__new__':
                continue
            script = f"""
from experiments.package_copy.test_review_regressions import PackageReview, package
from experiments.package_copy import owner as subject
root, owner = package(), subject.Owner()
namespace, name, _ = subject._PINS[{index}]
setattr(namespace, name, object())
PackageReview().refuse(root, owner)
"""
            result = subprocess.run([sys.executable, '-c', script], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_hierarchy_change_is_rejected(self):
        script = """
import pathlib
from experiments.package_copy.test_review_regressions import PackageReview, package
from experiments.package_copy import owner as subject
value, owner = package(), subject.Owner()
pathlib.PosixPath.__bases__ = tuple(reversed(pathlib.PosixPath.__bases__))
PackageReview().refuse(value, owner)
"""
        result = subprocess.run([sys.executable, '-c', script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_every_function_positional_and_keyword_default_pin(self):
        for function, _, _ in subject._FUNCTIONS:
            for attribute in ('__defaults__', '__kwdefaults__'):
                with self.subTest(function=function.__qualname__, attribute=attribute):
                    value, owner = package(), subject.Owner()
                    original = getattr(function, attribute)
                    replacement = (object(),) if attribute == '__defaults__' else {'injected': object()}
                    try:
                        setattr(function, attribute, replacement)
                        self.refuse(value, owner)
                    finally:
                        setattr(function, attribute, original)

    def test_dispatch_and_reducer_entries_and_table_aliases(self):
        for table in (subject._DISPATCH, subject._REDUCERS):
            for cls in subject._COPY_TYPES:
                with self.subTest(table=id(table), cls=cls):
                    value, owner = package(), subject.Owner()
                    with patch.dict(table, {cls: object()}):
                        self.refuse(value, owner)
        import copyreg
        for namespace, attribute in ((copy, '_deepcopy_dispatch'), (copy, 'dispatch_table'), (copyreg, 'dispatch_table')):
            value, owner = package(), subject.Owner()
            with patch.object(namespace, attribute, {}):
                self.refuse(value, owner)

    def test_class_slot_metadata_refused(self):
        for name, value in (('__slots__', ()), ('__slotnames__', ['foreign'])):
            root, owner = package(), subject.Owner()
            with patch.object(Package, name, value, create=True):
                self.refuse(root, owner)

    def test_cold_partial_and_foreign_consumed_slots_are_hook_free(self):
        events = []
        class Foreign:
            def __getattribute__(self, name):
                events.append(name)
                raise AssertionError('foreign hook')
            def __iter__(self):
                events.append('iter')
                raise AssertionError('foreign iteration')
            def __bool__(self):
                events.append('bool')
                raise AssertionError('foreign truth')
        if sys.version_info[:2] == (3, 12):
            root = package(); root.root = pathlib.PosixPath('/cold')
            self.refuse(root)
            self.assertFalse(hasattr(root.root, '_drv'))
            for name in ('_drv', '_root', '_tail_cached'):
                root = package(); delattr(root.root, name)
                before = {n: hasattr(root.root, n) for n in ('_drv', '_root', '_tail_cached')}
                self.refuse(root)
                self.assertEqual(before, {n: hasattr(root.root, n) for n in before})
            cases = (('_drv', Foreign()), ('_root', Foreign()), ('_tail_cached', Foreign()), ('_tail_cached', [Foreign()]))
        else:
            cases = (('_parts', Foreign()), ('_parts', [Foreign()]))
        for name, item in cases:
            root = package(); setattr(root.root, name, item)
            self.refuse(root)
        self.assertEqual(events, [])

    def test_unknown_roots_fields_and_subclasses_do_not_run_hooks(self):
        events = []
        class Foreign:
            def __getattribute__(self, name):
                events.append(name)
                raise AssertionError('foreign hook')
        class SubPath(pathlib.PosixPath):
            def __reduce__(self):
                events.append('reduce')
                raise AssertionError('subclass hook')
        class SubString(str):
            def __deepcopy__(self, memo):
                events.append('deepcopy')
                raise AssertionError('string hook')
        self.refuse(Foreign())
        for field, value in (('root', Foreign()), ('root', SubPath('/a')), ('name', SubString('x')), ('manifest_bytes', Foreign()), ('dependencies', {'x': Foreign()})):
            root = package(); setattr(root, field, value); self.refuse(root)
        root = package(); root.dependencies = root.__dict__; self.refuse(root)
        self.assertEqual(events, [])

    def test_shared_state_partial_output_and_real_counts(self):
        root = package(); other = package(); other.__dict__ = root.__dict__
        root.dependencies['second'] = other
        owner = subject.Owner(subject.Limits(package_copy_calls=26, package_copy_depth=5))
        result, events = self.observed(lambda: owner._authority_copy(subject._COPY, root, 'package'))
        self.assertEqual(len(events), 26)
        self.assertEqual(max(depth for _, depth in events), 5)
        self.assertEqual(owner.context.counts['package_copy_calls'], len(events))
        self.assertEqual(tuple(result.dependencies['second'].__dict__), ('root', 'name', 'version', 'entry', 'kind', 'source_root'))
        self.assertIsNot(result.__dict__, result.dependencies['second'].__dict__)
        self.assertIs(result.root, result.entry)
        if sys.version_info[:2] == (3, 12):
            self.assertFalse(hasattr(result.root, '_drv'))
        self.refuse(root, subject.Owner(subject.Limits(package_copy_calls=25)))
        self.refuse(root, subject.Owner(subject.Limits(package_copy_depth=4)))

    def test_cycle_memo_hit_depth_and_per_call_fresh_memo(self):
        root = package(); root.dependencies['self'] = root
        baseline, events = self.observed(lambda: subject._COPY(root))
        count = len(events); depth = max(d for _, d in events)
        owner = subject.Owner(subject.Limits(package_copy_calls=2 * count, package_copy_depth=depth))
        first, actual = self.observed(lambda: owner._authority_copy(subject._COPY, root, 'package'))
        second, actual2 = self.observed(lambda: owner._authority_copy(subject._COPY, root, 'package'))
        self.assertEqual(events, actual); self.assertEqual(events, actual2)
        self.assertIs(first.dependencies['self'], first)
        self.assertIs(second.dependencies['self'], second)
        self.assertIsNot(first, second)
        self.assertEqual(owner.context.counts['package_copy_calls'], 2 * count)
        self.refuse(root, owner)
        self.refuse(root, subject.Owner(subject.Limits(package_copy_depth=depth - 1)))

    def test_equal_distinct_paths_and_shared_dependency_dictionary(self):
        root = package(); left = package(); right = package(); leaf = package()
        root.dependencies.update(left=left, right=right, left_again=left)
        left.dependencies['leaf'] = leaf
        right.dependencies = left.dependencies
        expected, baseline = self.observed(lambda: subject._COPY(root))
        owner = subject.Owner()
        actual, events = self.observed(lambda: owner._authority_copy(subject._COPY, root, 'package'))
        self.assertEqual(events, baseline)
        self.assertEqual(owner.context.counts['package_copy_calls'], len(events))
        self.assertIs(actual.dependencies['left'], actual.dependencies['left_again'])
        self.assertIs(actual.dependencies['left'].dependencies, actual.dependencies['right'].dependencies)
        self.assertEqual(actual.root, actual.dependencies['left'].root)
        self.assertIsNot(actual.root, actual.dependencies['left'].root)

    def test_foreign_key_equality_is_not_invoked(self):
        events = []
        class Key:
            def __hash__(self): return hash('root')
            def __eq__(self, other):
                events.append('eq')
                raise AssertionError('foreign equality')
        root = package()
        del root.__dict__['root']
        root.__dict__[Key()] = root.entry
        events.clear()
        self.refuse(root)
        self.assertEqual(events, [])
        root = package(); root.dependencies[Key()] = root
        events.clear(); self.refuse(root)
        self.assertEqual(events, [])

    def test_none_and_empty_path_have_exact_call_counts(self):
        owner = subject.Owner(subject.Limits(package_copy_calls=1, package_copy_depth=1))
        result, events = self.observed(lambda: owner._authority_copy(subject._COPY, None, 'package'))
        self.assertIsNone(result); self.assertEqual(events, [(type(None), 1)])
        root = package(); path = pathlib.PosixPath(); _ = path.parts
        root.root = root.entry = root.source_root = path
        owner = subject.Owner()
        result, events = self.observed(lambda: owner._authority_copy(subject._COPY, root, 'package'))
        self.assertEqual(len(events), 19)
        self.assertEqual(owner.context.counts['package_copy_calls'], 19)

    def test_seeded_alias_cycles_match_every_logical_depth_event(self):
        import random
        for seed in range(50):
            with self.subTest(seed=seed):
                rng = random.Random(seed)
                nodes = [package() for _ in range(6)]
                for index, node in enumerate(nodes):
                    for edge in range(rng.randrange(4)):
                        node.dependencies[str(edge)] = rng.choice(nodes)
                    if index and rng.randrange(3) == 0:
                        node.dependencies = rng.choice(nodes[:index]).dependencies
                    if index and rng.randrange(4) == 0:
                        node.__dict__ = rng.choice(nodes[:index]).__dict__
                _, baseline = self.observed(lambda: subject._COPY(nodes[0]))
                owner = subject.Owner()
                projected = []
                admit = owner.context.admit_package_call
                def record(depth):
                    projected.append(depth)
                    admit(depth)
                owner.context.admit_package_call = record
                _, actual = self.observed(lambda: owner._authority_copy(subject._COPY, nodes[0], 'package'))
                self.assertEqual(actual, baseline)
                self.assertEqual(projected, [depth for _, depth in actual])

    def test_component_container_and_string_subclasses_are_not_called(self):
        events = []
        class Tail(list):
            def __iter__(self):
                events.append('iter')
                raise AssertionError('tail hook')
        class Component(str):
            def __deepcopy__(self, memo):
                events.append('deepcopy')
                raise AssertionError('component hook')
        slot = '_parts' if sys.version_info[:2] == (3, 11) else '_tail_cached'
        for tail in (Tail(['a']), [Component('a')]):
            root = package(); setattr(root.root, slot, tail)
            self.refuse(root)
        self.assertEqual(events, [])

    def test_unused_path_slots_are_not_traversed(self):
        root = package()
        if sys.version_info[:2] == (3, 12):
            root.root._raw_paths = object()
        else:
            root.root._pparts = object()
        owner = subject.Owner()
        result, events = self.observed(lambda: owner._authority_copy(subject._COPY, root, 'package'))
        self.assertEqual(owner.context.counts['package_copy_calls'], len(events))
        self.assertIs(result.root, result.entry)


if __name__ == '__main__':
    unittest.main()
