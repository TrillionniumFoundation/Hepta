"""Independent authority-map review controls. Repository root must be on PYTHONPATH."""
import copy
from dataclasses import replace
from functools import partial
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta import modules, packages
from experiments.owned_loader import owner as owned
from experiments.authority_maps.owner import Owner, Limits, _DEEPCOPY
from experiments.request_load.context import Rejected

TEXT = 'fn main()->Unit effects {} {}'


class AuthorityReview(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.entry = self.root / 'main.hepta'
        self.entry.write_text(TEXT)

    def direct(self, value, name='package_state', **limits):
        owner = Owner(Limits(**limits))
        result = owner._authority_copy(copy.deepcopy, value, name)
        return owner, result

    def root_calls(self, action):
        calls = []
        previous = sys.getprofile()
        def observe(frame, event, argument):
            if (event == 'call' and frame.f_code is _DEEPCOPY.__code__
                    and frame.f_back.f_code is Owner._authority_copy.__code__):
                calls.append(type(frame.f_locals['x']).__name__)
        sys.setprofile(observe)
        try:
            action()
        finally:
            sys.setprofile(previous)
        return calls

    def test_none_is_only_admitted_as_package_state_root(self):
        owner, result = self.direct(None, authority_visits=1, authority_depth=1)
        self.assertIsNone(result)
        self.assertEqual(owner.context.counts['authority_visits'], 1)
        for name, value in [('source_bytes', None), ('bindings', None),
                            ('package_state', {'x': None})]:
            with self.subTest(name=name, value=value), self.assertRaises(Rejected):
                self.direct(value, name)

    def test_only_three_exact_value_shapes(self):
        for name, value in [('source_bytes', {'x': ''}), ('bindings', {'x': b''}),
                            ('bindings', {'x': {}}), ('source_bytes', {'x': {}}),
                            ('package_state', {'x': b''}), ('package_state', {'x': []}),
                            ('package_state', {'x': True}), ('package_state', 'string')]:
            with self.subTest(name=name, value=value), self.assertRaises(Rejected):
                self.direct(value, name)

    def test_bytes_leaf_is_atomic_and_lengths_do_not_change_visits(self):
        for size in (0, 1, 100000):
            value = {'x' * (size + 1): b'x' * size}
            owner, result = self.direct(value, 'source_bytes', authority_visits=3)
            self.assertEqual(owner.context.counts['authority_visits'], 3)
            key = next(iter(value))
            self.assertIs(next(iter(result)), key)
            self.assertIs(result[key], value[key])
            self.assertIsNot(result, value)

    def test_unknown_metaclass_never_hashes_compares_or_resolves_hooks(self):
        events = []
        class Meta(type):
            def __hash__(self):
                events.append('hash'); raise AssertionError('hash')
            def __eq__(self, other):
                events.append('eq'); raise AssertionError('eq')
        class Evil(metaclass=Meta):
            def __getattribute__(self, name):
                events.append(name); raise AssertionError('getattribute')
        owner = Owner()
        def refuse():
            with self.assertRaisesRegex(Rejected, 'unknown'):
                owner._authority_copy(copy.deepcopy, {'evil': Evil()}, 'package_state')
        self.assertEqual(self.root_calls(refuse), [])
        self.assertEqual(events, [])

    def test_subclass_hooks_never_execute(self):
        events = []
        class DictSubclass(dict):
            def items(self): events.append('items'); raise AssertionError('items')
            def __deepcopy__(self, memo): events.append('copy'); raise AssertionError('copy')
        class StrSubclass(str):
            def __deepcopy__(self, memo): events.append('copy'); raise AssertionError('copy')
        class BytesSubclass(bytes):
            def __deepcopy__(self, memo): events.append('copy'); raise AssertionError('copy')
        examples = [(DictSubclass(x='x'), 'package_state'),
                    ({'x': DictSubclass()}, 'package_state'),
                    ({'x': StrSubclass('v')}, 'bindings'),
                    ({'x': BytesSubclass(b'v')}, 'source_bytes'),
                    ({StrSubclass('x'): 'v'}, 'package_state')]
        for value, name in examples:
            with self.subTest(name=name, root=type(value)), self.assertRaises(Rejected):
                self.direct(value, name)
        self.assertEqual(events, [])

    def test_invalid_key_rejects_without_hashing_or_equality_during_preflight(self):
        events = []
        class Key:
            def __hash__(self): events.append('hash'); return 17
            def __eq__(self, other): events.append('eq'); return False
            def __deepcopy__(self, memo): events.append('copy'); return self
        value = {Key(): 'v'}
        events.clear()
        with self.assertRaisesRegex(Rejected, 'keys'):
            self.direct(value)
        self.assertEqual(events, [])

    def test_self_and_mutual_cycles_reject_before_copy(self):
        one = {}; one['self'] = one
        first = {}; second = {'back': first}; first['next'] = second
        for value in (one, first):
            owner = Owner()
            def refuse():
                with self.assertRaisesRegex(Rejected, 'cyclic'):
                    owner._authority_copy(copy.deepcopy, value, 'package_state')
            self.assertEqual(self.root_calls(refuse), [])
            self.assertTrue(owner.context.closed)

    def test_expanded_alias_budget_not_unique_count_but_memo_alias_preserved(self):
        shared = {'leaf': 'v'}
        graph = {'left': shared, 'right': shared}
        owner, result = self.direct(graph, authority_visits=9)
        self.assertEqual(owner.context.counts['authority_visits'], 9)
        self.assertIs(result['left'], result['right'])
        self.assertIsNot(result['left'], shared)
        denied = Owner(Limits(authority_visits=8))
        def refuse():
            with self.assertRaisesRegex(Rejected, 'authority_visits'):
                denied._authority_copy(copy.deepcopy, graph, 'package_state')
        self.assertEqual(self.root_calls(refuse), [])
        self.assertEqual(denied.context.counts['authority_visits'], 8)

    def test_repeated_copy_roots_use_independent_fresh_memos(self):
        value = {'x': 'v'}
        owner = Owner()
        binding = owner._authority_copy(copy.deepcopy, value, 'bindings')
        state = owner._authority_copy(copy.deepcopy, value, 'package_state')
        self.assertEqual(binding, state)
        self.assertIsNot(binding, state)
        self.assertIs(next(iter(binding)), next(iter(state)))
        self.assertEqual(owner.context.counts['authority_visits'], 6)

    def test_depth_counts_keys_and_leafs_not_only_containers(self):
        for name, value in [('source_bytes', {'a': b'x'}), ('bindings', {'a': 'x'})]:
            with self.subTest(name=name), self.assertRaisesRegex(Rejected, 'authority_depth'):
                self.direct(value, name, authority_depth=1)
            owner, _ = self.direct(value, name, authority_depth=2)
            self.assertEqual(owner.context.counts['authority_visits'], 3)
        shared = {'leaf': 'v'}
        graph = {'shallow': shared, 'deep': {'nested': shared}}
        owner, _ = self.direct(graph, authority_depth=4)
        with self.assertRaisesRegex(Rejected, 'authority_depth'):
            self.direct(graph, authority_depth=3)

    def test_iterative_preflight_rejects_deep_input_without_recursing(self):
        graph = 'v'
        for _ in range(5000): graph = {'next': graph}
        owner = Owner(Limits(authority_depth=50))
        def refuse():
            with self.assertRaisesRegex(Rejected, 'authority_depth'):
                owner._authority_copy(copy.deepcopy, graph, 'package_state')
        self.assertEqual(self.root_calls(refuse), [])
        self.assertTrue(owner.context.closed)

    def test_large_breadth_stops_at_budget_before_any_copy(self):
        value = {str(i): str(i) for i in range(20000)}
        owner = Owner(Limits(authority_visits=11))
        def refuse():
            with self.assertRaisesRegex(Rejected, 'authority_visits'):
                owner._authority_copy(copy.deepcopy, value, 'bindings')
        self.assertEqual(self.root_calls(refuse), [])
        self.assertEqual(owner.context.counts['authority_visits'], 11)

    def test_bytes_dispatch_and_reducer_patches_never_execute(self):
        for table in (copy._deepcopy_dispatch, copy.dispatch_table):
            events = []
            def hook(*args): events.append('hook'); return b'changed'
            with patch.dict(table, {bytes: hook}):
                owner = Owner()
                def refuse():
                    with self.assertRaisesRegex(Rejected, 'bytes'):
                        owner._authority_copy(copy.deepcopy, {'x': b'bytes'}, 'source_bytes')
                self.assertEqual(self.root_calls(refuse), [])
            self.assertEqual(events, [])

    def test_entry_checkpoint_cannot_replace_bytes_dispatch_before_pin(self):
        events = []
        def hook(*args): events.append('hook'); return b'changed'
        old = copy._deepcopy_dispatch[bytes]
        def checkpoint(): copy._deepcopy_dispatch[bytes] = hook
        try:
            owner = Owner(checkpoint=checkpoint)
            with self.assertRaisesRegex(Rejected, 'bytes'):
                owner._authority_copy(copy.deepcopy, {'x': b'bytes'}, 'source_bytes')
        finally:
            copy._deepcopy_dispatch[bytes] = old
        self.assertEqual(events, [])
        self.assertEqual(owner.context.counts['authority_visits'], 0)
        self.assertTrue(owner.context.closed)

    def test_only_entry_and_exit_checkpoints_surround_entire_preflight_copy(self):
        owner = Owner()
        checkpoints = []
        owner.context.checkpoint = lambda: checkpoints.append(owner.context.counts['authority_visits'])
        owner._authority_copy(copy.deepcopy, {'a': {'b': 'c'}}, 'package_state')
        self.assertEqual(checkpoints, [0, 5])

    def test_post_copy_cancel_keeps_charges_and_closes_context(self):
        owner = Owner()
        def checkpoint():
            if owner.context.counts['authority_visits']:
                raise TimeoutError('cancelled after map copy')
        owner.context.checkpoint = checkpoint
        def cancel():
            with self.assertRaisesRegex(TimeoutError, 'after map'):
                owner._authority_copy(copy.deepcopy, {'x': b'x'}, 'source_bytes')
        self.assertEqual(self.root_calls(cancel), ['dict'])
        self.assertEqual(owner.context.counts['authority_visits'], 3)
        self.assertTrue(owner.context.closed)
        with self.assertRaisesRegex(Rejected, 'terminal'):
            owner.load(self.entry)

    def test_copy_recursion_failure_is_terminal_and_consumes_preflight(self):
        value = 'v'
        for _ in range(100): value = {'x': value}
        owner = Owner(Limits(authority_depth=101))
        limit = sys.getrecursionlimit()
        try:
            sys.setrecursionlimit(120)
            with self.assertRaises(RecursionError):
                owner._authority_copy(copy.deepcopy, value, 'package_state')
        finally:
            sys.setrecursionlimit(limit)
        self.assertEqual(owner.context.counts['authority_visits'], 201)
        self.assertTrue(owner.context.closed)

    def test_unknown_map_name_rejected_without_copy(self):
        events = []
        def copier(value): events.append('copy'); return value
        owner = Owner()
        with self.assertRaisesRegex(Rejected, 'unknown authority map name'):
            owner._authority_copy(copier, {}, 'surprise')
        self.assertEqual(events, [])

    def test_package_copy_exclusion_is_real_and_failure_cannot_publish_handle(self):
        graph = modules.load_project(self.entry)
        events = []
        error = LookupError('package failed')
        class PackageBomb:
            def __deepcopy__(self, memo): events.append('package'); raise error
        graph.package = PackageBomb()
        owner = Owner()
        with patch.object(modules, '_load_project', return_value=graph):
            with self.assertRaises(LookupError) as caught:
                owner.load(self.entry)
        self.assertIs(caught.exception, error)
        self.assertEqual(events, ['package'])
        self.assertEqual(owner.context.counts['authority_visits'], 7)
        self.assertEqual(owner._handles, [])
        self.assertTrue(owner.context.closed)
        self.assertFalse(owner._busy)

    def test_later_map_failure_does_not_roll_back_completed_earlier_copy_work(self):
        graph = modules.load_project(self.entry)
        graph.bindings = {'x': b'bad'}
        owner = Owner()
        def refuse():
            with patch.object(modules, '_load_project', return_value=graph):
                with self.assertRaisesRegex(Rejected, 'bindings values'):
                    owner.load(self.entry)
        self.assertEqual(self.root_calls(refuse), ['dict'])
        self.assertEqual(owner.context.counts['authority_visits'], 5)
        self.assertEqual(owner._handles, [])
        self.assertTrue(owner.context.closed)

    def test_three_map_budget_is_cumulative_over_loads(self):
        owner = Owner(Limits(authority_visits=13))
        first = owner.load(self.entry)
        self.assertEqual(owner.context.counts['authority_visits'], 7)
        with self.assertRaisesRegex(Rejected, 'authority_visits'):
            owner.load(self.entry)
        self.assertEqual(owner.context.counts['authority_visits'], 13)
        self.assertEqual(len(owner._handles), 1)
        self.assertIs(owner._handles[0][0], first)
        with self.assertRaisesRegex(Rejected, 'terminal'):
            first.unchanged()

    def test_locked_package_success_uses_only_string_nested_map_snapshot(self):
        (self.root / 'hepta.toml').write_text('[package]\nname="review"\nversion="1.0.0"\nsource_root="."\nentry="main.hepta"\n')
        packages.write_lock(self.root)
        owner = Owner()
        actual = owner.load(self.entry, locked=True)
        expected = modules.load_project(self.entry, locked=True)
        self.assertEqual(actual.project.report(), expected.report())
        # P=1, E=0, F=2; three root counts: source=3, bindings=3, snapshot=25.
        self.assertEqual(owner.context.counts['authority_visits'], 31)
        self.assertTrue(actual.unchanged())


    def test_terminal_context_refuses_package_delegate_without_running_it(self):
        owner = Owner()
        with self.assertRaises(Rejected):
            owner._authority_copy(copy.deepcopy, [], 'package_state')
        events = []
        def copier(value): events.append('package'); return value
        with self.assertRaisesRegex(Rejected, 'terminal'):
            owner._authority_copy(copier, object(), 'package')
        self.assertEqual(events, [])

    def test_custom_map_name_rejected_without_equality_hook(self):
        events = []
        class Name(str):
            def __eq__(self, other): events.append('eq'); return False
        owner = Owner()
        with self.assertRaises(Rejected):
            owner._authority_copy(copy.deepcopy, {}, Name('package'))
        self.assertEqual(events, [])
        self.assertEqual(owner.context.counts['authority_visits'], 0)

    def test_real_load_four_root_calls_have_fresh_memos_and_distinct_dicts(self):
        graph = modules.load_project(self.entry)
        shared = {}
        for name in ('source_bytes', 'bindings', 'package_state', 'package'):
            setattr(graph, name, shared)
        owner = Owner()
        calls = []
        previous = sys.getprofile()
        def observe(frame, event, argument):
            if (event == 'call' and frame.f_code is _DEEPCOPY.__code__
                    and frame.f_back.f_code in
                    (Owner._authority_copy.__code__, owned.Owner._authority_copy.__code__)):
                calls.append((frame.f_locals['x'], frame.f_locals['memo']))
        with patch.object(modules, '_load_project', return_value=graph):
            sys.setprofile(observe)
            try:
                handle = owner.load(self.entry)
            finally:
                sys.setprofile(previous)
        self.assertEqual(len(calls), 4)
        self.assertTrue(all(value is shared and memo is None for value, memo in calls))
        authority = owner._handles[0][1]
        copied = [getattr(authority, name) for name in
                  ('source_bytes', 'bindings', 'package_state', 'package')]
        self.assertEqual(len({id(value) for value in copied}), 4)
        self.assertTrue(all(value == shared and value is not shared for value in copied))
        self.assertIs(handle.project, graph)
        self.assertEqual(owner.context.counts['authority_visits'], 3)


class LegacySeamReview(unittest.TestCase):
    def test_direct_seam_releases_temporaries_before_catch_with_traceback_retained(self):
        for fail in (False, True):
            events = []
            class Operation(partial):
                def __del__(self): events.append('callable finalized')
            class Argument:
                def __del__(self): events.append('argument finalized')
            class Namespace:
                @property
                def deepcopy(self): return Operation(int if fail else id)
            held_exception = None
            try:
                owned.Owner()._authority_copy(Namespace().deepcopy, Argument(), 'source_bytes')
            except TypeError as error:
                held_exception = error
                events.append('caught')
            self.assertEqual(events, ['callable finalized', 'argument finalized'] + (['caught'] if fail else []))
            if fail: self.assertIsNotNone(held_exception.__traceback__)

    def test_real_legacy_load_preserves_capture_argument_cleanup_and_setattr_order(self):
        for failure in (None, 'call', 'argument', 'setattr'):
            with self.subTest(failure=failure):
                events = []
                class Operation(partial):
                    def __del__(self): events.append('callable finalized:' + self.label)
                class Argument:
                    def __del__(self): events.append('argument finalized')
                class Authority:
                    def __setattr__(self, name, value):
                        events.append('set:' + name)
                        if failure == 'setattr': raise LookupError('setattr')
                        object.__setattr__(self, name, value)
                authority = Authority()
                class Namespace:
                    label = 'old'
                    def copy(self, graph): return authority
                    @property
                    def deepcopy(self):
                        events.append('capture:' + self.label)
                        operation = Operation(int if failure == 'call' else id)
                        operation.label = self.label
                        return operation
                namespace = Namespace()
                class Graph:
                    def __getattr__(self, name):
                        events.append('argument:' + name)
                        namespace.label = 'new'
                        if failure == 'argument': raise LookupError('argument')
                        return Argument()
                owner = owned.Owner()
                held_exception = None
                with patch.object(owned, 'copy', namespace), patch.object(modules, '_load_project', return_value=Graph()):
                    try:
                        owner.load('unused')
                    except (TypeError, LookupError) as error:
                        held_exception = error
                        events.append('caught')
                start = ['capture:old', 'argument:source_bytes', 'callable finalized:old']
                if failure != 'argument': start.append('argument finalized')
                if failure not in ('argument', 'call'): start.append('set:source_bytes')
                if failure:
                    self.assertEqual(events, start + ['caught'])
                    self.assertIsNotNone(held_exception.__traceback__)
                    self.assertEqual(owner._handles, [])
                    self.assertTrue(owner.context.closed)
                else:
                    self.assertEqual(events[:5], start)
                    self.assertEqual(events[5:10], ['capture:new', 'argument:bindings',
                        'callable finalized:new', 'argument finalized', 'set:bindings'])
                    self.assertEqual(sum(e.startswith('capture:') for e in events), 4)
                    self.assertEqual(sum(e.startswith('set:') for e in events), 4)


if __name__ == '__main__':
    unittest.main(verbosity=2)
