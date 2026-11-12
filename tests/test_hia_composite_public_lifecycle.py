"""Real selected-native public lifetime controls, with weak observations only.

The allocation-failure case separately injects MemoryError after actual earlier
buffers were allocated. All semantic success/refusal cases execute real images.
No observer retains a native session or ctypes buffer through a strong reference.
"""
from contextlib import ExitStack
from copy import deepcopy
import ctypes
import gc
import os
import unittest
from unittest.mock import patch
import weakref

from hepta import hia_program_composite as composite
from hepta.hia_composite_functions_native import (
    NativeFunctionSession, SELECTOR, WORKSPACE_BYTES, OUTPUT_BYTES)
from hepta.hia_composite_types_native import (
    NativeCompositeTypeSession, SESSION_BYTES, OUTPUT_BYTES as TYPE_OUTPUT_BYTES)
from hepta.hia_program import HIAProgramRejected, verify_program
from tests.hia_composite_function_fixture import composite_function_fixture
from tests.test_hia_composite_functions_native import HOST_METHODS, absent
from tests.test_hia_program import b, f, i, ret
from tests.test_hia_program_composite import module, record, stored_loan_program, task_program


class _WeakLifetimeObservation:
    """Forward real calls; retain only weakrefs, integer sizes and booleans."""

    def __init__(self, *, fail_size=None):
        self.fail_size = fail_size
        self.fault = MemoryError('explicit partial-allocation lifetime control')
        self.injected = 0
        self.sessions = {'function': [], 'types': []}
        self.buffers = []
        self.closed = []
        self.stack = ExitStack()

    def __enter__(self):
        original_buffer = ctypes.create_string_buffer
        sizes = {WORKSPACE_BYTES, OUTPUT_BYTES, SESSION_BYTES, TYPE_OUTPUT_BYTES}

        def observed_buffer(initial, size=None):
            if type(initial) is int and size is None and initial in sizes:
                if initial == self.fail_size:
                    self.injected += 1
                    raise self.fault
                value = original_buffer(initial)
                self.buffers.append((initial, weakref.ref(value)))
                return value
            return original_buffer(initial, size)

        self.stack.enter_context(patch.object(ctypes, 'create_string_buffer', new=observed_buffer))
        for cls, key, fields in (
                (NativeFunctionSession, 'function', ('_workspace', '_output')),
                (NativeCompositeTypeSession, 'types', ('_state', '_output'))):
            original_init, original_close = cls.__init__, cls.close

            def constructor(original, kind):
                def observed(instance, *args, **kwargs):
                    self.sessions[kind].append(weakref.ref(instance))
                    return original(instance, *args, **kwargs)
                return observed

            def closer(original, kind, names):
                def observed(instance):
                    original(instance)
                    original(instance)  # Exercise real idempotent cleanup.
                    self.closed.append((kind, instance._closed,
                                        all(getattr(instance, name) is None for name in names)))
                return observed

            self.stack.enter_context(patch.object(cls, '__init__', new=constructor(original_init, key)))
            self.stack.enter_context(patch.object(cls, 'close', new=closer(original_close, key, fields)))
        return self

    def __exit__(self, *args):
        return self.stack.__exit__(*args)

    def assert_released(self, case):
        # A caller can retain the exception and its traceback while collecting
        # unrelated cycles. Sessions reachable through it must already be closed.
        gc.collect()
        for kind, fields in (('function', ('_workspace', '_output')),
                             ('types', ('_state', '_output'))):
            for reference in self.sessions[kind]:
                instance = reference()
                if instance is not None:
                    case.assertTrue(instance._closed, kind)
                    for field in fields:
                        case.assertIsNone(getattr(instance, field), (kind, field))
                del instance
        case.assertTrue(all(closed and empty for _, closed, empty in self.closed))
        for size, reference in self.buffers:
            case.assertIsNone(reference(), 'retained native allocation: ' + str(size))


def outcome(document):
    try:
        result = verify_program(document)
    except HIAProgramRejected as error:
        return ('rejected', error.code, str(error)), error
    return ('accepted', result.canonical_bytes, result.structured_bytes), result


class CompositePublicLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture = composite_function_fixture()
        cls.environment = fixture.environment
        cls.reference_environment = {**fixture.environment, SELECTOR: ''}

    def poison_host_owners(self, stack):
        stack.enter_context(patch.object(composite, '_Types', new=absent))
        for name in HOST_METHODS:
            stack.enter_context(patch.object(composite._Elaborator, name, new=absent))

    def test_public_success_and_held_rejections_release_every_native_session(self):
        simple = module([], f('run', [], [], [], [b('entry', [], [], ret())]))
        absent_field = deepcopy(simple); absent_field.pop('types')
        invalid_types = deepcopy(simple); invalid_types['types'] = 0
        invalid_functions = deepcopy(simple); invalid_functions['functions'] = []
        invalid_blocks = deepcopy(simple); invalid_blocks['functions'][0]['blocks'] = None
        delegated = deepcopy(simple)
        delegated['functions'][0]['blocks'].append(b('later', [('x', 'MissingType')], [], ret()))
        primitive = deepcopy(simple)
        primitive['functions'][0]['blocks'][0]['ops'] = [i('const', [], [('x', 'u8')], value=256)]
        cases = (
            ('stored-loan success', stored_loan_program(), True),
            ('task/helper success', task_program(), True),
            ('before native allocation', absent_field, False),
            ('native type initialization refusal', invalid_types, False),
            ('later nominal constructor refusal', invalid_functions, False),
            ('native function refusal', invalid_blocks, False),
            ('delegated native parameter refusal', delegated, False),
            ('final primitive refusal', primitive, False),
        )
        for label, document, accepts in cases:
            with self.subTest(label=label):
                original = deepcopy(document)
                with patch.dict(os.environ, self.reference_environment):
                    expected, reference_result = outcome(deepcopy(document))
                del reference_result
                with patch.dict(os.environ, self.environment), ExitStack() as stack, \
                        _WeakLifetimeObservation() as observed:
                    self.poison_host_owners(stack)
                    actual, held = outcome(document)
                    self.assertEqual(actual, expected)
                    self.assertEqual(actual[0] == 'accepted', accepts)
                    self.assertEqual(document, original)
                    if not accepts:
                        self.assertIsInstance(held, HIAProgramRejected)
                        self.assertIsNotNone(held.__traceback__)
                    observed.assert_released(self)
                    if label == 'before native allocation':
                        self.assertEqual(observed.buffers, [])
                    else:
                        self.assertTrue(observed.sessions['types'])
                        self.assertTrue(observed.buffers)
                    if label in ('stored-loan success', 'task/helper success', 'native function refusal',
                                 'delegated native parameter refusal', 'final primitive refusal'):
                        self.assertTrue(observed.sessions['function'])
                    # The exception/result remains held until after all weak
                    # buffer and closed-session assertions have completed.
                    self.assertIsNotNone(held)
                del held

    def test_private_function_failures_keep_live_state_and_repeat_exactly(self):
        document = module([record('Pair', [('first', 'u8'), ('second', 'u8')])],
            f('run', [('pair', 'Pair')], [], [], [b('entry', [('pair', 'Pair')], [
            i('const', [], [('one', 'u8')], value=1),
            i('int.add.checked', ['missing', 'one'], [('two', 'u8')]),
        ], ret())]))
        owners = []
        try:
            with patch.dict(os.environ, self.reference_environment):
                reference = composite._Elaborator(deepcopy(document)); owners.append(reference)
            with patch.dict(os.environ, self.environment):
                native = composite._Elaborator(deepcopy(document)); owners.append(native)
            previous_serial = native.serial
            for _ in range(2):
                with self.assertRaises(HIAProgramRejected) as expected:
                    reference._reference_function(reference.document['functions'][0])
                with patch.object(composite._Elaborator, '_reference_function', new=absent), \
                        self.assertRaises(HIAProgramRejected) as actual:
                    native.function(native.document['functions'][0])
                self.assertEqual((actual.exception.code, str(actual.exception)),
                                 (expected.exception.code, str(expected.exception)))
                self.assertEqual((native.serial, native.value_slots, native.types.observations,
                                  native.helpers, native.helper_names),
                                 (reference.serial, reference.value_slots, reference.types.observations,
                                  reference.helpers, reference.helper_names))
                self.assertGreater(native.serial, previous_serial)
                previous_serial = native.serial
                self.assertFalse(native._native_function_session._closed)
                self.assertFalse(native.types._closed)
                self.assertEqual(ctypes.sizeof(native._native_function_session._workspace), WORKSPACE_BYTES)
                self.assertEqual(ctypes.sizeof(native.types._state), SESSION_BYTES)
        finally:
            for owner in owners:
                if owner._native_function_session is not None:
                    owner._native_function_session.close()
                    owner._native_function_session.close()
                owner.types.close(); owner.types.close()

    def test_partly_allocated_real_buffers_release_with_memory_error_held(self):
        document = module([], f('run', [], [], [], [b('entry', [], [], ret())]))
        for failing_size in (SESSION_BYTES, OUTPUT_BYTES):
            with self.subTest(failing_size=failing_size), patch.dict(os.environ, self.environment), \
                    ExitStack() as stack, _WeakLifetimeObservation(fail_size=failing_size) as observed:
                self.poison_host_owners(stack)
                held = None
                try:
                    verify_program(deepcopy(document))
                except MemoryError as error:
                    held = error
                self.assertIs(held, observed.fault)
                self.assertEqual(str(held), 'explicit partial-allocation lifetime control')
                self.assertIsNotNone(held.__traceback__)
                self.assertEqual(observed.injected, 1)
                self.assertTrue(observed.buffers)  # Earlier allocations were real.
                observed.assert_released(self)
                if failing_size == OUTPUT_BYTES:
                    self.assertTrue(observed.sessions['function'])
                    self.assertTrue(any(size == WORKSPACE_BYTES for size, _ in observed.buffers))


if __name__ == '__main__':
    unittest.main()
