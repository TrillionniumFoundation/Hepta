"""Independent shallow-authority review; run with candidate root on PYTHONPATH."""
import copy
import copyreg
from functools import partial
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta import modules
from experiments.owned_loader import owner as legacy
from experiments.shallow_authority import owner as subject
from experiments.request_load.context import Rejected


def graph():
    # Values intentionally do not pretend to be a valid loader graph. The
    # tested operation copies only eleven canonical state entries.
    return modules.LoadedProject(None, None, {}, {}, 'identity', [], None,
                                 None, False, {}, [])


class ShallowReview(unittest.TestCase):
    def direct(self, value=None, **limits):
        owner = subject.Owner(subject.Limits(**limits))
        value = graph() if value is None else value
        return owner, owner._authority_shallow(copy.copy, value)

    def observed(self, action):
        calls = []
        original = sys.getprofile()
        def profile(frame, event, argument):
            if event == 'call' and frame.f_code is subject._COPY.__code__:
                calls.append(frame.f_locals['x'])
        sys.setprofile(profile)
        try:
            action()
        finally:
            sys.setprofile(original)
        return calls

    def refused(self, owner, value, pattern=''):
        def run():
            with self.assertRaisesRegex(Rejected, pattern):
                owner._authority_shallow(subject._COPY, value)
        self.assertEqual(self.observed(run), [])
        self.assertTrue(owner.context.closed)

    def test_exact_state_transfer_preserves_original_self_and_state_aliases(self):
        value = graph()
        value.program = value
        value.sources = value.__dict__
        value.modules = value.c_imports
        owner, result = self.direct(value, shallow_fields=11)
        self.assertIsNot(result, value)
        self.assertIsNot(result.__dict__, value.__dict__)
        self.assertIs(result.program, value)
        self.assertIs(result.sources, value.__dict__)
        self.assertIs(result.modules, result.c_imports)
        self.assertIs(result.modules, value.modules)
        self.assertEqual(owner.context.counts['shallow_fields'], 11)
        for name, item in value.__dict__.items():
            self.assertIs(result.__dict__[name], item)

    def test_opaque_values_never_resolve_attributes_copy_iterate_compare_or_hash(self):
        events = []
        class Meta(type):
            def __hash__(self): events.append('class hash'); raise AssertionError()
            def __eq__(self, other): events.append('class eq'); raise AssertionError()
        class Payload(metaclass=Meta):
            def __getattribute__(self, name): events.append(name); raise AssertionError()
            def __iter__(self): events.append('iter'); raise AssertionError()
            def __hash__(self): events.append('hash'); raise AssertionError()
            def __eq__(self, other): events.append('eq'); raise AssertionError()
        value = graph()
        payload = Payload()
        for name in value.__dict__: value.__dict__[name] = payload
        owner, result = self.direct(value)
        self.assertEqual(events, [])
        self.assertTrue(all(item is payload for item in result.__dict__.values()))
        self.assertEqual(owner.context.counts['shallow_fields'], 11)

    def test_deep_cycles_and_large_payload_do_not_expand_field_units(self):
        value = graph()
        nested = []
        for _ in range(10000): nested = [nested]
        nested.append(nested)
        value.program = nested
        value.sources = b'x' * 1_000_000
        owner, result = self.direct(value)
        self.assertIs(result.program, nested)
        self.assertIs(result.sources, value.sources)
        self.assertEqual(owner.context.counts['shallow_fields'], 11)

    def test_unknown_root_and_subclass_are_refused_without_unknown_hooks(self):
        events = []
        class Meta(type):
            def __hash__(self): events.append('hash'); raise AssertionError()
            def __eq__(self, other): events.append('eq'); raise AssertionError()
        class Foreign(metaclass=Meta):
            def __getattribute__(self, name): events.append(name); raise AssertionError()
        class Derived(modules.LoadedProject):
            def __copy__(self): events.append('copy'); raise AssertionError()
        for value in (Foreign(), object.__new__(Derived), {}, None):
            self.refused(subject.Owner(), value, 'exact LoadedProject')
        self.assertEqual(events, [])

    def test_instance_protocol_shadow_and_extra_or_missing_field_refuse(self):
        events = []
        for shadow in ('__copy__', '__reduce__', '__reduce_ex__', '__getstate__', '__getnewargs__'):
            value = graph()
            value.__dict__[shadow] = lambda *args: events.append(shadow)
            self.refused(subject.Owner(), value, 'state shape')
        for key in ('program', 'identity'):
            value = graph(); del value.__dict__[key]
            self.refused(subject.Owner(), value, 'state shape')
        self.assertEqual(events, [])

    def test_noncanonical_key_never_runs_hash_equality_or_str(self):
        events = []
        class Key:
            def __hash__(self): events.append('hash'); return 17
            def __eq__(self, other): events.append('eq'); return False
            def __str__(self): events.append('str'); raise AssertionError()
        value = graph(); del value.__dict__['program']
        value.__dict__[Key()] = None
        events.clear()
        self.refused(subject.Owner(), value, 'state key')
        self.assertEqual(events, [])

    def test_string_subclass_key_never_runs_equality(self):
        events = []
        class Key(str):
            __hash__ = str.__hash__
            def __eq__(self, other): events.append('eq'); return str.__eq__(self, other)
        value = graph(); item = value.__dict__.pop('program')
        value.__dict__[Key('program')] = item
        events.clear()
        self.refused(subject.Owner(), value, 'state key')
        self.assertEqual(events, [])

    def test_state_dict_subclass_never_runs_its_methods(self):
        events = []
        class State(dict):
            def __len__(self): events.append('len'); raise AssertionError()
            def __iter__(self): events.append('iter'); raise AssertionError()
            def items(self): events.append('items'); raise AssertionError()
        value = graph(); value.__dict__ = State(value.__dict__)
        self.refused(subject.Owner(), value, 'state shape')
        self.assertEqual(events, [])

    def test_mutable_finite_class_hooks_refused_without_invocation(self):
        events = []
        def hostile(*args, **kwargs): events.append('called'); raise AssertionError()
        value = graph()
        for name in subject._HOOK_NAMES:
            # __dict__ is read-only on type objects. Replacing __new__ then
            # deleting it does not restore CPython's original tp_new slot,
            # so that hook has an isolated process below.
            if name in ('__dict__', '__new__'): continue
            with self.subTest(name=name), patch.object(subject._CLASS, name, hostile, create=True):
                self.refused(subject.Owner(), value, 'class hook')
        self.assertEqual(events, [])
        probe = '''
import copy
from experiments.shallow_authority import owner as s
from experiments.request_load.context import Rejected
value=object.__new__(s._CLASS)
for name in s._FIELDS: value.__dict__[name]=None
events=[]
s._CLASS.__new__=lambda *args: events.append('new')
owner=s.Owner()
try: owner._authority_shallow(copy.copy,value)
except Rejected: pass
else: raise AssertionError('replacement new was accepted')
assert events == [] and owner.context.closed
'''
        result = subprocess.run([sys.executable, '-B', '-c', probe], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_descriptor_dict_is_refused_before_get(self):
        events = []
        class Descriptor:
            def __get__(self, obj, cls=None): events.append('get'); raise AssertionError()
        value = graph()
        # __dict__ on a Python class is read-only; test descriptor-bearing
        # __getstate__, which is equally part of the finite policy.
        with patch.object(subject._CLASS, '__getstate__', Descriptor()):
            self.refused(subject.Owner(), value, 'class hook')
        self.assertEqual(events, [])

    def test_slot_metadata_refused_without_iterating(self):
        events = []
        class Slots:
            def __iter__(self): events.append('iter'); raise AssertionError()
        class Names(list):
            def __len__(self): events.append('len'); raise AssertionError()
        value = graph()
        for name, item in [('__slots__', Slots()), ('__slotnames__', ['program']),
                           ('__slotnames__', Names()), ('__slotnames__', ())]:
            with self.subTest(name=name, kind=type(item).__name__), patch.object(subject._CLASS, name, item, create=True):
                self.refused(subject.Owner(), value, 'slot metadata')
        self.assertEqual(events, [])

    def test_empty_none_and_missing_slot_cache_remain_accepted(self):
        for item in (None, []):
            with patch.object(subject._CLASS, '__slotnames__', item, create=True):
                owner, result = self.direct()
                self.assertEqual(owner.context.counts['shallow_fields'], 11)
                self.assertIs(type(result), subject._CLASS)

    def test_dispatch_reducer_and_helper_replacements_never_run(self):
        events = []
        def hostile(*args, **kwargs): events.append('called'); raise AssertionError()
        value = graph()
        for table in (copy._copy_dispatch, copy.dispatch_table):
            with patch.dict(table, {subject._CLASS: hostile}):
                self.refused(subject.Owner(), value, 'dispatch')
        for namespace, name, _ in subject._HELPERS:
            with self.subTest(name=name), patch.object(namespace, name, hostile):
                self.refused(subject.Owner(), value, 'helper')
        self.assertEqual(events, [])

    def test_dispatch_table_replacements_refuse_before_methods(self):
        events = []
        class Table(dict):
            def get(self, *args): events.append('get'); raise AssertionError()
        value = graph()
        for name in ('_copy_dispatch', 'dispatch_table'):
            with patch.object(copy, name, Table()):
                self.refused(subject.Owner(), value, 'dispatch')
        self.assertEqual(events, [])

    def test_captured_copier_identity_and_module_copy_identity_refused(self):
        events = []
        def hostile(*args): events.append('called'); raise AssertionError()
        owner = subject.Owner()
        with self.assertRaisesRegex(Rejected, 'captured shallow copier'):
            owner._authority_shallow(hostile, graph())
        with patch.object(copy, 'copy', hostile):
            self.refused(subject.Owner(), graph(), 'shallow authority hook')
        self.assertEqual(events, [])

    def test_canonical_constructor_init_is_not_called(self):
        value = graph(); events = []
        def hostile(*args, **kwargs): events.append('init'); raise AssertionError()
        with patch.object(subject._CLASS, '__init__', hostile):
            _, result = self.direct(value)
        self.assertIs(type(result), subject._CLASS)
        self.assertEqual(events, [])

    def test_quota_boundaries_and_no_refund_after_partial_second_admission(self):
        for limit in (1, 10):
            owner = subject.Owner(subject.Limits(shallow_fields=limit))
            self.refused(owner, graph(), 'shallow_fields')
            self.assertEqual(owner.context.counts['shallow_fields'], limit)
        owner = subject.Owner(subject.Limits(shallow_fields=21))
        owner._authority_shallow(copy.copy, graph())
        self.refused(owner, graph(), 'shallow_fields')
        self.assertEqual(owner.context.counts['shallow_fields'], 21)
        owner = subject.Owner(subject.Limits(shallow_fields=22))
        first = owner._authority_shallow(copy.copy, graph())
        second = owner._authority_shallow(copy.copy, graph())
        self.assertIsNot(first, second)
        self.assertEqual(owner.context.counts['shallow_fields'], 22)

    def test_positive_exact_integer_limit(self):
        for value in (0, -1, True, False, 1.0, '11', None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                subject.Limits(shallow_fields=value)

    def test_entry_checkpoint_shape_mutation_is_inspected(self):
        value = graph()
        def checkpoint(): value.__dict__['extra'] = None
        owner = subject.Owner(checkpoint=checkpoint)
        self.refused(owner, value, 'state shape')
        self.assertEqual(owner.context.counts['shallow_fields'], 0)

    def test_entry_checkpoint_hook_mutation_is_rejected_before_copy(self):
        events = []
        def hostile(*args): events.append('hook'); raise AssertionError()
        def checkpoint(): copy._copy_dispatch[subject._CLASS] = hostile
        with patch.dict(copy._copy_dispatch):
            owner = subject.Owner(checkpoint=checkpoint)
            self.refused(owner, graph(), 'dispatch')
        self.assertEqual(events, [])

    def test_only_entry_and_exit_checkpoints_and_exit_failure_keeps_charge(self):
        events = []
        owner = subject.Owner(checkpoint=lambda: events.append(owner.context.counts['shallow_fields']))
        owner._authority_shallow(copy.copy, graph())
        self.assertEqual(events, [0, 11])
        calls = []
        def checkpoint():
            calls.append(owner.context.counts['shallow_fields'])
            if len(calls) == 2: raise KeyboardInterrupt('after copy')
        owner = subject.Owner(checkpoint=checkpoint)
        def fail():
            with self.assertRaisesRegex(KeyboardInterrupt, 'after copy'):
                owner._authority_shallow(copy.copy, graph())
        self.assertEqual(len(self.observed(fail)), 1)
        self.assertEqual(calls, [0, 11])
        self.assertTrue(owner.context.closed)
        self.assertEqual(owner.context.counts['shallow_fields'], 11)

    def test_swallowed_checkpoint_reentrant_failure_cannot_reopen(self):
        calls = []
        def checkpoint():
            try: owner._authority_shallow(copy.copy, graph())
            except Rejected: calls.append('swallowed')
        owner = subject.Owner(checkpoint=checkpoint)
        self.refused(owner, graph(), 'terminal')
        self.assertEqual(calls, ['swallowed'])

    def test_terminal_direct_call_runs_neither_checkpoint_nor_copier(self):
        events = []
        owner = subject.Owner(checkpoint=lambda: events.append('checkpoint'))
        owner.context.closed = True
        self.refused(owner, graph(), 'terminal')
        self.assertEqual(events, [])
        self.assertEqual(owner.context.counts['shallow_fields'], 0)

    def test_load_shallow_failure_precedes_all_authority_maps_and_no_handle(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'main.hepta'
            path.write_text('fn main()->Unit effects {} {}')
            owner = subject.Owner(subject.Limits(shallow_fields=10))
            with self.assertRaisesRegex(Rejected, 'shallow_fields'): owner.load(path)
            self.assertEqual(owner.context.counts['authority_visits'], 0)
            self.assertEqual(owner._handles, [])
            self.assertTrue(owner.context.closed)
            self.assertFalse(owner._busy)


class LegacyShallowReview(unittest.TestCase):
    def test_direct_call_temporary_finalization_with_retained_copy_exception(self):
        for failure in (False, True):
            events = []
            class Operation(partial):
                def __del__(self): events.append('callable finalized')
            class Argument:
                def __del__(self): events.append('argument finalized')
            class Namespace:
                @property
                def copy(self): return Operation(int if failure else id)
            held = None
            try:
                legacy.Owner()._authority_shallow(Namespace().copy, Argument())
            except TypeError as error:
                held = error; events.append('caught')
            self.assertEqual(events, ['callable finalized', 'argument finalized'] + (['caught'] if failure else []))
            if failure: self.assertIsNotNone(held.__traceback__)

    def test_capture_and_argument_failure_match_original_expression(self):
        def scenario(use_seam, failure):
            events = []
            class Operation(partial):
                def __del__(self): events.append('callable finalized')
            class Argument:
                def __del__(self): events.append('argument finalized')
            class Namespace:
                @property
                def copy(self):
                    events.append('capture')
                    if failure == 'capture': raise LookupError('capture')
                    return Operation(int if failure == 'copier' else id)
            def argument():
                events.append('argument')
                if failure == 'argument': raise LookupError('argument')
                return Argument()
            held = None
            try:
                if use_seam: legacy.Owner()._authority_shallow(Namespace().copy, argument())
                else: Namespace().copy(argument())
            except (LookupError, TypeError) as error:
                held = error; events.append('caught')
            return events, held
        for failure in (None, 'capture', 'argument', 'copier'):
            baseline, baseline_error = scenario(False, failure)
            candidate, candidate_error = scenario(True, failure)
            self.assertEqual(candidate, baseline)
            self.assertIs(type(candidate_error), type(baseline_error))
            if candidate_error:
                self.assertEqual(str(candidate_error), str(baseline_error))
                self.assertIsNotNone(candidate_error.__traceback__)

    def test_real_load_legacy_shallow_failure_stops_before_deepcopy(self):
        events = []
        class Operation(partial):
            def __del__(self): events.append('shallow callable finalized')
        class Namespace:
            @property
            def copy(self): events.append('capture shallow'); return Operation(int)
            @property
            def deepcopy(self): events.append('capture deep'); raise AssertionError()
        owner = legacy.Owner(); held = None
        with patch.object(legacy, 'copy', Namespace()), patch.object(modules, '_load_project', return_value=object()):
            try: owner.load('unused')
            except TypeError as error: held = error; events.append('caught')
        self.assertEqual(events, ['capture shallow', 'shallow callable finalized', 'caught'])
        self.assertIsNotNone(held.__traceback__)
        self.assertEqual(owner._handles, [])
        self.assertTrue(owner.context.closed)
        self.assertFalse(owner._busy)


if __name__ == '__main__': unittest.main(verbosity=2)
