"""Real five-owner public lifetimes, with weak native-buffer observations."""
from contextlib import ExitStack
from copy import deepcopy
import ctypes
import gc
import os
import struct
import unittest
from unittest.mock import patch
import weakref

from hepta import hia_program_composite as composite
from hepta.hia_composite_constructor_native import NativeConstructorInvocation
from hepta.hia_composite_constructor_native import SELECTOR as CONSTRUCTOR_SELECTOR
from hepta.hia_composite_functions_native import NativeFunctionSession, SELECTOR as FUNCTION_SELECTOR
from hepta.hia_composite_outer_native import NativeOuterInvocation, SELECTOR as OUTER_SELECTOR
from hepta.hia_composite_types_native import NativeCompositeTypeSession
from hepta.hia_program import HIAProgramRejected, verify_program
from tests.hia_composite_function_fixture import composite_function_fixture
from tests.test_hia_composite_outer_integration import HOST, forbidden
from tests.test_hia_composite_public_lifecycle import outcome
from tests.test_hia_program import b, f, i, ret
from tests import test_hia_program_composite as nominal


class WeakNominalObservation:
    """Forward real constructors; never retain a session or buffer strongly."""
    roles = ((NativeConstructorInvocation, 'constructor', ('_workspace', '_output', '_empty')),
             (NativeOuterInvocation, 'outer', ('_workspace', '_output', '_empty', '_function_workspace')),
             (NativeFunctionSession, 'function', ('_workspace', '_output')),
             (NativeCompositeTypeSession, 'types', ('_state', '_output')))

    def __init__(self, fail_role=None):
        self.fail_role = fail_role
        self.fault = MemoryError('explicit nominal owner partial-allocation control')
        self.injected = 0
        self.constructing = []
        self.objects = {role: [] for _, role, _ in self.roles}
        self.buffers = []
        self.stack = ExitStack()

    def __enter__(self):
        create = ctypes.create_string_buffer
        def allocate(value, size=None):
            role = self.constructing[-1] if self.constructing else None
            if type(value) is int and size is None and role is not None:
                if role == self.fail_role and value == 65536:
                    self.injected += 1
                    raise self.fault
                buffer = create(value)
                self.buffers.append((role, value, weakref.ref(buffer)))
                return buffer
            return create(value, size)
        self.stack.enter_context(patch.object(ctypes, 'create_string_buffer', new=allocate))
        for cls, role, _ in self.roles:
            original = cls.__init__
            def constructor(original, role):
                def observed(instance, *args, **kwargs):
                    self.objects[role].append(weakref.ref(instance))
                    self.constructing.append(role)
                    try:
                        return original(instance, *args, **kwargs)
                    finally:
                        self.constructing.pop()
                return observed
            self.stack.enter_context(patch.object(cls, '__init__', new=constructor(original, role)))
        for cls in (NativeFunctionSession, NativeCompositeTypeSession):
            original = cls.close
            def closer(original):
                def twice(instance):
                    original(instance)
                    original(instance)
                return twice
            self.stack.enter_context(patch.object(cls, 'close', new=closer(original)))
        return self

    def __exit__(self, *args):
        return self.stack.__exit__(*args)

    def assert_released(self, case):
        gc.collect()
        for _, role, fields in self.roles:
            for reference in self.objects[role]:
                instance = reference()
                if instance is not None:
                    for name in fields:
                        case.assertIsNone(getattr(instance, name, None), (role, name))
                    if role in ('function', 'types'):
                        case.assertTrue(instance._closed, role)
                del instance
        for role, size, reference in self.buffers:
            case.assertIsNone(reference(), ('native allocation remains held', role, size))


class CompleteNominalLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture = composite_function_fixture()
        cls.fixture = fixture
        cls.env = fixture.complete_environment
        cls.reference_env = {**cls.env, CONSTRUCTOR_SELECTOR: '',
                             FUNCTION_SELECTOR: '', OUTER_SELECTOR: ''}

    def poison(self, stack):
        stack.enter_context(patch.object(composite, '_Types', new=forbidden))
        for name in HOST:
            stack.enter_context(patch.object(composite._Elaborator, name, new=forbidden))

    def test_public_success_and_held_refusals_release_every_owner_workspace(self):
        simple = nominal.module([], f('run', [], [], [], [b('entry', [], [], ret())]))
        shape = deepcopy(simple); shape.pop('types')
        types = deepcopy(simple); types['types'] = 0
        inventory = deepcopy(simple); inventory['functions'] = []
        function = deepcopy(simple); function['functions'][0]['blocks'] = None
        delegated = deepcopy(simple)
        delegated['functions'][0]['blocks'].append(b('later', [('x', 'MissingType')], [], ret()))
        primitive = deepcopy(simple)
        primitive['functions'][0]['blocks'][0]['ops'] = [i('const', [], [('x', 'u8')], value=256)]
        choice = nominal.enum('Choice', [('a', []), ('b', [])])
        blocks = [b('entry', [('value', 'Choice')], [],
                    nominal.match('value', ('a', 'one', []), ('b', 'two', []))),
                  b('one', [], [], ret()), b('two', [], [], ret())]
        blocks += [b('unused_' + str(index), [], [], ret()) for index in range(4093)]
        outer_limit = nominal.module([choice], f('huge', [('value', 'Choice')], [], [], blocks))
        cases = [('stored success', nominal.stored_loan_program(), True),
                 ('task success', nominal.task_program(), True),
                 ('constructor shape', shape, False), ('type init', types, False),
                 ('constructor inventory', inventory, False), ('function rejection', function, False),
                 ('delegated parameter', delegated, False), ('primitive final check', primitive, False),
                 ('outer final block limit', outer_limit, False)]
        for label, document, accepts in cases:
            with self.subTest(label=label):
                original = deepcopy(document)
                with patch.dict(os.environ, self.reference_env):
                    expected, reference = outcome(deepcopy(document))
                del reference
                with patch.dict(os.environ, self.env), ExitStack() as stack, WeakNominalObservation() as observed:
                    self.poison(stack)
                    actual, held = outcome(document)
                    self.assertEqual(actual, expected)
                    self.assertEqual(actual[0] == 'accepted', accepts)
                    self.assertEqual(document, original)
                    if not accepts:
                        self.assertIsNotNone(held.__traceback__)
                    self.assertTrue(observed.objects['constructor'])
                    if label in ('stored success', 'task success', 'function rejection',
                                 'delegated parameter', 'primitive final check', 'outer final block limit'):
                        self.assertTrue(observed.objects['outer'])
                        self.assertTrue(any(role == 'outer' and size == 80 << 20
                                            for role, size, _ in observed.buffers))
                    observed.assert_released(self)
                    self.assertIsNotNone(held)
                del held

    def test_real_type_init_before_unpublished_protocol_refusal_releases_type_state(self):
        image = self.fixture.constructor_bundle.images['owner']
        entry = image._entry
        faults = []
        def corrupt(source, size, output, capacity, workspace, workspace_size):
            extent = entry(source, size, output, capacity, workspace, workspace_size)
            if extent == 64:
                frame = struct.unpack_from('<8Q', output)
                if frame[1] == 0 and frame[3:5] == (10, 2):
                    faults.append(True)
                    struct.pack_into('<Q', output, 0, frame[0] ^ 1)
            return extent
        document = nominal.module([], f('run', [], [], [], [b('entry', [], [], ret())]))
        with patch.dict(os.environ, self.env), ExitStack() as stack, WeakNominalObservation() as observed:
            self.poison(stack)
            stack.enter_context(patch.object(image, '_entry', new=corrupt))
            stack.enter_context(patch('hepta.hia_composite_constructor_native.selected_composite_constructor',
                                      new=lambda: self.fixture.constructor_bundle))
            held = None
            try:
                verify_program(document)
            except HIAProgramRejected as error:
                held = error
            self.assertIsNotNone(held)
            self.assertEqual(held.code, 'E_HIA_TYPE')
            self.assertEqual(faults, [True])
            self.assertTrue(observed.objects['types'])
            self.assertEqual(observed.objects['function'], [])
            observed.assert_released(self)
            self.assertIsNotNone(held.__traceback__)

    def test_partial_real_constructor_and_outer_allocations_release_with_error_held(self):
        document = nominal.module([], f('run', [], [], [], [b('entry', [], [], ret())]))
        for role in ('constructor', 'outer'):
            with self.subTest(role=role), patch.dict(os.environ, self.env), ExitStack() as stack, \
                    WeakNominalObservation(fail_role=role) as observed:
                self.poison(stack)
                held = None
                try:
                    verify_program(deepcopy(document))
                except MemoryError as error:
                    held = error
                self.assertIs(held, observed.fault)
                self.assertIsNotNone(held.__traceback__)
                self.assertEqual(observed.injected, 1)
                expected_size = (192 if role == 'constructor' else 80) << 20
                self.assertTrue(any(kind == role and size == expected_size
                                    for kind, size, _ in observed.buffers))
                observed.assert_released(self)


if __name__ == '__main__':
    unittest.main()
