"""Source controls for the interpreter's hosted context-manager descriptor boundary."""
from collections import deque
import json
import os
from pathlib import Path
import subprocess
import sys
import types
import unittest
from hepta import hia_emission_native as emission
from hepta import hia_store_artifact_profile_native as profile
from hepta import hia_store_transaction_native as transaction
HELPERS = (emission._context_special, profile._context_special, transaction._context_special)

def _observe(factory, helper=None, outer=False):
    manager, events = factory()
    outcome = {}
    outer_error = KeyError('outer-handler') if outer else None
    def execute():
        if helper is None:
            with manager:
                events.append('unexpected-body')
        else:
            bound = {}
            for phase in emission._runtime_context_lookup_order():
                name = '__enter__' if phase == 1 else '__exit__'
                bound[name] = helper(manager, name)
            events.append('unexpected-complete-protocol')
    def invoke():
        try:
            execute()
        except BaseException as error:
            get = BaseException.__getattribute__
            outcome.update(error_type=type(error).__name__, args=get(error, 'args'),
                cause_is_none=get(error, '__cause__') is None,
                context_is_outer=get(error, '__context__') is outer_error,
                context_type=None if get(error, '__context__') is None else type(get(error, '__context__')).__name__,
                suppressed=get(error, '__suppress_context__'))
        else:
            outcome['unexpected_success'] = True
    if outer:
        try:
            raise outer_error
        except KeyError:
            invoke()
            outcome['outer_restored'] = sys.exception() is outer_error
    else:
        invoke()
    return {'events': events, 'outcome': outcome}

def _factory(missing, *, name='ManagerName', qualname='Outer.ManagerQualname',
             module='context.fixture', asynchronous='none', metaclass=type, string_class=str):
    def construct():
        events = []
        class Present:
            def __get__(self, instance, owner):
                events.append('present.lookup')
                return lambda *args: events.append('unexpected-present-call')
        class UnusedAsync:
            def __get__(self, instance, owner):
                events.append('unexpected-async-lookup')
                raise AssertionError('the async descriptor must not bind')
        attributes = {'__qualname__': string_class(qualname), '__module__': module}
        attributes['__exit__' if missing == '__enter__' else '__enter__'] = Present()
        if asynchronous == 'descriptors':
            attributes.update(__aenter__=UnusedAsync(), __aexit__=UnusedAsync())
        elif asynchronous == 'functions':
            attributes.update(__aenter__=lambda *a: None, __aexit__=lambda *a: None)
        elif asynchronous == 'one-descriptor':
            attributes['__aenter__'] = UnusedAsync()
        elif asynchronous == 'one-nondescriptor':
            attributes.update(__aenter__=None, __aexit__=UnusedAsync())
        elif asynchronous == 'both-nondescriptors':
            attributes.update(__aenter__=None, __aexit__=None)
        kind = metaclass(string_class(name), (), attributes)
        return kind(), events
    return construct

class ContextProtocolSourceTests(unittest.TestCase):
    def compare(self, factory, *, outer=False):
        expected = _observe(factory, outer=outer)
        self.assertNotIn('unexpected_success', expected['outcome'])
        for helper in HELPERS:
            with self.subTest(helper=helper.__module__):
                self.assertEqual(_observe(factory, helper, outer), expected)

    def test_missing_enter_and_exit_match_runtime_names_unicode_and_long_types(self):
        for missing in ('__enter__', '__exit__'):
            for name, qualname, module in (
                ('Short', 'Outer.Different', 'context.fixture'),
                ('Renamed', 'Actual.Qualified', '__main__'),
                ('雪'*90, '外层.雪'*90, '模块.雪'),
                ('N'*420, 'Q'*420, 'M'*420),
                ("quote'newline\n", "outer.quote'newline\n", "mod'newline\n"),
                ('B', 'Builtins.Qualname', 'builtins'),
                ('NonString', 'Outer.NonString', None),
                ('NumberModule', 'Outer.NumberModule', 7),
            ):
                with self.subTest(missing=missing, name=name[:20], module=module):
                    self.compare(_factory(missing, name=name, qualname=qualname, module=module))

    def test_static_builtin_types_use_the_actual_full_type_name(self):
        for create in (object, lambda: None, list, dict, lambda: (), lambda: range(0),
                       types.SimpleNamespace, deque, lambda: iter(()), lambda: NotImplemented):
            self.compare(lambda create=create: (create(), []))

    def test_renamed_heap_type_keeps_distinct_name_and_qualified_name(self):
        for missing in ('__enter__', '__exit__'):
            def factory(missing=missing):
                value, events = _factory(missing)()
                kind = type(value)
                type.__setattr__(kind, '__name__', 'NameChangedAfterCreation')
                type.__setattr__(kind, '__qualname__', 'Outer.QualnameChangedAfterCreation')
                return value, events
            self.compare(factory)

    def test_metaclass_and_string_subclass_hooks_are_not_invoked(self):
        observed = []
        class HostileMeta(type):
            def __getattribute__(cls, name):
                observed.append(('metaclass.getattribute', name))
                raise AssertionError('metaclass lookup participated')
            def __repr__(cls):
                observed.append(('metaclass.repr',))
                raise AssertionError('metaclass repr participated')
        class HostileString(str):
            def __str__(self):
                observed.append(('string.str',))
                raise AssertionError('string conversion participated')
            def __eq__(self, other):
                observed.append(('string.eq',))
                raise AssertionError('string equality participated')
            def __format__(self, format_spec):
                observed.append(('string.format',))
                raise AssertionError('string formatting participated')
        for missing in ('__enter__', '__exit__'):
            for module in (HostileString('context.module'), HostileString('__main__'),
                           HostileString('builtins'), object()):
                self.compare(_factory(missing, name='HostileName', qualname='Hostile.Qualified',
                    module=module, metaclass=HostileMeta, string_class=HostileString))
        self.assertEqual(observed, [])

    def test_async_suggestions_observe_presence_without_binding_user_descriptors(self):
        for missing in ('__enter__', '__exit__'):
            for asynchronous in ('none', 'descriptors', 'functions', 'one-descriptor',
                                 'one-nondescriptor', 'both-nondescriptors'):
                with self.subTest(missing=missing, asynchronous=asynchronous):
                    self.compare(_factory(missing, asynchronous=asynchronous))

    def test_private_diagnostic_does_not_replace_the_active_exception_chain(self):
        for missing in ('__enter__', '__exit__'):
            self.compare(_factory(missing, asynchronous='descriptors'), outer=True)

    def test_typename_primitive_does_not_dispatch_instance_format_string_or_attribute_hooks(self):
        for missing in ('__enter__', '__exit__'):
            def factory(missing=missing):
                manager, events = _factory(missing)()
                def forbidden(*args):
                    events.append('unexpected-object-protocol')
                    raise AssertionError('user object protocol participated')
                kind = type(manager)
                for name in ('__format__', '__str__', '__repr__', '__getattribute__'):
                    type.__setattr__(kind, name, forbidden)
                return manager, events
            self.compare(factory)

    def test_present_descriptor_errors_keep_the_original_exception_identity(self):
        for name in ('__enter__', '__exit__'):
            for helper in HELPERS:
                error = TypeError('actual descriptor error')
                events = []
                class FailingDescriptor:
                    def __get__(self, instance, owner):
                        events.append(name)
                        raise error
                kind = type('PresentButRaises', (), {name: FailingDescriptor()})
                manager = kind()
                with self.assertRaises(TypeError) as caught:
                    helper(manager, name)
                self.assertIs(caught.exception, error)
                self.assertEqual(events, [name])

    def test_missing_protocol_keeps_original_garbage_and_user_type_lifetimes(self):
        script = r'''
import gc, json, sys, weakref
from hepta import hia_emission_native as emission
from hepta import hia_store_artifact_profile_native as profile
from hepta import hia_store_transaction_native as transaction
selector, missing, warm, asynchronous = json.loads(sys.argv[1])
helpers = (None, emission._context_special, profile._context_special, transaction._context_special)
helper = helpers[selector]
def inert(*arguments):
    return None
attributes = {'__module__': 'gc.context', '__qualname__': 'Held.Manager'}
attributes['__exit__' if missing == '__enter__' else '__enter__'] = inert
if asynchronous:
    attributes.update(__aenter__=inert, __aexit__=inert)
kind = type('HeldManager', (), attributes)
manager = kind()
def reject(value):
    try:
        if helper is None:
            with value:
                raise AssertionError('unexpected context body')
        else:
            for phase in emission._runtime_context_lookup_order():
                helper(value, '__enter__' if phase == 1 else '__exit__')
            raise AssertionError('unexpected complete protocol')
    except TypeError as error:
        return {'type': type(error).__name__, 'args': error.args,
                'cause_is_none': error.__cause__ is None,
                'context_is_none': error.__context__ is None}
def user_lifetime():
    user_attributes = dict(attributes, __module__='user.context', __qualname__='Transient.Manager')
    user_kind = type('TransientManager', (), user_attributes)
    user_manager = user_kind()
    references = weakref.ref(user_kind), weakref.ref(user_manager)
    outcome = reject(user_manager)
    return references, outcome
emission._runtime_context_lookup_order()
if warm:
    emission._runtime_context_qualified_name()
    emission._runtime_context_missing_suffix(missing, asynchronous)
automatic_collection = gc.isenabled()
gc.disable()
try:
    gc.collect()
    outcome = reject(manager)
    collected = gc.collect()
    references, user_outcome = user_lifetime()
    user_collected = gc.collect()
    print(json.dumps({'outcome': outcome, 'collected': collected,
        'user_outcome': user_outcome, 'user_collected': user_collected,
        'user_class_released': references[0]() is None,
        'user_instance_released': references[1]() is None}, sort_keys=True))
finally:
    if automatic_collection:
        gc.enable()
'''
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith('HEPTA_HIA_') and key not in ('PYTHONPATH', 'PYTHONHOME')}
        environment['PYTHONDONTWRITEBYTECODE'] = '1'
        def observe(selector, missing, warm, asynchronous):
            result = subprocess.run(
                [sys.executable, '-B', '-c', script, json.dumps([selector, missing, warm, asynchronous])],
                cwd=Path(__file__).resolve().parents[1], env=environment,
                capture_output=True, text=True, timeout=10, check=True)
            self.assertEqual(result.stderr, '')
            return json.loads(result.stdout)
        for missing in ('__enter__', '__exit__'):
            for warm in (False, True):
                for asynchronous in (False, True):
                    expected = observe(0, missing, warm, asynchronous)
                    self.assertTrue(expected['user_class_released'])
                    self.assertTrue(expected['user_instance_released'])
                    for selector, helper in enumerate(HELPERS, 1):
                        with self.subTest(helper=helper.__module__, missing=missing,
                                          warm=warm, asynchronous=asynchronous):
                            self.assertEqual(observe(selector, missing, warm, asynchronous), expected)

if __name__ == '__main__':
    unittest.main()
