"""Independent routing controls for the two retained nominal owner families.

These are source and Python transport controls. Recording owners never execute
an HIA image; the small ctypes buffers below exercise the real close methods,
not native type/function semantics or a cold-qualified cross-family pipeline.
The separate native suites retain responsibility for those execution claims.
"""
from __future__ import annotations

import ast
from contextlib import ExitStack
import ctypes
from hashlib import sha256
import inspect
import os
from pathlib import Path
import tempfile
import textwrap
from threading import RLock
import unittest
from unittest.mock import Mock, patch
import weakref

from hepta import hia_program_composite as composite
from hepta import hia_composite_constructor_native as main_constructor
from hepta import hia_composite_functions_native as main_function
from hepta import hia_composite_outer_native as main_outer
from hepta import hia_composite_types_native as native_types
from hepta import hia_nominal_admission_native as admission
from hepta import hia_nominal_function_native as nominal_function
from hepta import hia_nominal_module_native as nominal_module
from hepta.hia_program import HIAProgramRejected
from tests.test_hia_program import b, c, f, ret


CONSTRUCTOR_SELECTORS = (admission.SELECTOR, main_constructor.SELECTOR)
FUNCTION_SELECTORS = (nominal_function.SELECTOR, main_function.SELECTOR)
MODULE_SELECTORS = (nominal_module.SELECTOR, main_outer.SELECTOR)


class _RecordingOwner:
    """Deliberately false-valued: selection uses identity with None."""

    def __init__(self, **attributes):
        self.__dict__.update(attributes)

    def __bool__(self):
        return False


def _document():
    return {
        'schema': composite.SCHEMA, 'module': 'owner_routes', 'types': [],
        'functions': [f('constant', [], ['u32'], [], [
            b('entry', [], [c('answer', 'u32', 37)], ret('answer'))])],
    }


def _transport_sessions(*, function=True):
    """Real close implementations with small, non-executable transport arenas."""
    types = native_types.NativeCompositeTypeSession.__new__(
        native_types.NativeCompositeTypeSession)
    types._lock, types._closed = RLock(), False
    types._output = ctypes.create_string_buffer(64)
    types._state = ctypes.create_string_buffer(64)
    references = [weakref.ref(types._output), weakref.ref(types._state)]
    session = None
    if function:
        session = main_function.NativeFunctionSession.__new__(
            main_function.NativeFunctionSession)
        session._lock, session._closed = RLock(), False
        session.types = types
        session._workspace = ctypes.create_string_buffer(64)
        session._output = ctypes.create_string_buffer(64)
        session._source_index, session._function_sources = {}, {}
        references.extend((weakref.ref(session._workspace), weakref.ref(session._output)))
    return types, session, references


class NominalOwnerRouteTests(unittest.TestCase):
    def setUp(self):
        # Test the named routes even when a surrounding actual-native gate has
        # many selectors installed. Restore every caller setting afterwards.
        self.enterContext(patch.dict(os.environ, {
            key: value for key, value in os.environ.items()
            if not key.startswith('HEPTA_HIA_')
        }, clear=True))

    def assert_refusal(self, callback, message):
        with self.assertRaisesRegex(HIAProgramRejected, message) as caught:
            callback()
        self.assertEqual(caught.exception.code, 'E_HIA_TYPE')

    def test_both_original_function_oracles_keep_their_independent_hashes(self):
        expected = (
            (composite._Elaborator._reference_function,
             'c4725d8619bcb0ad80b34878ed64d327c58a054f90a088e9cfa9357ebb006075'),
            (composite._Elaborator._reference_main_function,
             '843ee6257a7c09078c4883f2bf1a10443ef6e7c9d2818cf3566fda453c929745'),
        )
        for method, digest in expected:
            with self.subTest(method=method.__name__):
                node = ast.parse(textwrap.dedent(inspect.getsource(method))).body[0]
                body = ast.Module(body=node.body, type_ignores=[])
                self.assertEqual(sha256(ast.dump(body, include_attributes=False).encode()).hexdigest(),
                                 digest)
        original = inspect.getsource(composite._Elaborator._reference_main_function)
        original = original.replace('def _reference_main_function(', 'def function(', 1)
        self.assertEqual(sha256((original.rstrip('\n') + '\n').encode()).hexdigest(),
                         'b7336fb540911f220fef676d082c1a365d4712703ba5f08faeff3ac985913972')

    def test_parallel_constructor_selectors_refuse_before_any_owner(self):
        owner = object.__new__(composite._Elaborator)
        with patch.dict(os.environ, dict.fromkeys(CONSTRUCTOR_SELECTORS, 'selected')), \
                patch.object(admission, 'selected_nominal_admission') as ours, \
                patch.object(main_constructor, 'selected_composite_constructor') as theirs, \
                patch.object(composite._Elaborator, '_reference_initialize') as reference:
            self.assert_refusal(lambda: composite._Elaborator.__init__(owner, _document()),
                                'conflicting native constructor owners')
            for callback in (ours, theirs, reference):
                callback.assert_not_called()
        self.assertEqual(vars(owner), {})

    def test_parallel_function_selectors_refuse_after_constructor_before_session(self):
        owner, document = object.__new__(composite._Elaborator), _document()

        def initialize(instance, value, *, legacy=False):
            instance.document = value

        with patch.dict(os.environ, dict.fromkeys(FUNCTION_SELECTORS, 'selected')), \
                patch.object(composite._Elaborator, '_reference_initialize', new=initialize), \
                patch.object(main_function, 'selected_composite_functions') as selected, \
                patch.object(nominal_function, 'selected_nominal_function') as ours:
            self.assert_refusal(lambda: composite._Elaborator.__init__(owner, document),
                                'conflicting native function owners')
            selected.assert_not_called()
            ours.assert_not_called()
        self.assertEqual(vars(owner), {'document': document})

    def test_parallel_module_selectors_refuse_before_any_owner(self):
        owner = object.__new__(composite._Elaborator)
        with patch.dict(os.environ, dict.fromkeys(MODULE_SELECTORS, 'selected')), \
                patch.object(nominal_module, 'selected_nominal_module') as ours, \
                patch.object(main_outer, 'selected_composite_outer') as theirs, \
                patch.object(composite._Elaborator, '_reference_lower') as reference:
            self.assert_refusal(owner.lower, 'conflicting native module owners')
            for callback in (ours, theirs, reference):
                callback.assert_not_called()
        self.assertEqual(vars(owner), {})

    def test_empty_selectors_preserve_the_default_public_result(self):
        document = _document()
        expected = composite.elaborate_program(document)
        with patch.dict(os.environ, dict.fromkeys(
                CONSTRUCTOR_SELECTORS + FUNCTION_SELECTORS + MODULE_SELECTORS, '')):
            self.assertEqual(composite.elaborate_program(document), expected)

    def test_all_three_successful_constructors_install_main_session_once(self):
        for route in ('reference', 'admission', 'main'):
            for legacy in (False, True):
                with self.subTest(route=route, legacy=legacy), ExitStack() as stack:
                    document, events, session = object(), [], object()

                    def initialize(owner, value, *, legacy=False):
                        events.append(('constructor', owner, value, legacy))
                        owner.document = value

                    def install(owner, *, legacy=False):
                        self.assertIs(owner.document, document)
                        self.assertNotIn('_native_function_session', vars(owner))
                        events.append(('session', owner, legacy))
                        return session

                    ours = _RecordingOwner(initialize=Mock(side_effect=initialize))
                    theirs = _RecordingOwner(initialize=Mock(side_effect=initialize))
                    functions = _RecordingOwner(session=Mock(side_effect=install))
                    environment = {main_function.SELECTOR: 'recording-main-functions'}
                    if route != 'reference':
                        environment[admission.SELECTOR if route == 'admission' else
                                    main_constructor.SELECTOR] = 'recording-constructor'
                    stack.enter_context(patch.dict(os.environ, environment))
                    stack.enter_context(patch.object(admission, 'selected_nominal_admission',
                                                     return_value=ours if route == 'admission' else None))
                    stack.enter_context(patch.object(main_constructor, 'selected_composite_constructor',
                                                     return_value=theirs if route == 'main' else None))
                    stack.enter_context(patch.object(composite._Elaborator, '_reference_initialize',
                                                     new=initialize))
                    selected = stack.enter_context(patch.object(main_function,
                        'selected_composite_functions', return_value=functions))
                    owner = composite._Elaborator(document, legacy=legacy)
                    self.assertEqual(events, [('constructor', owner, document, legacy),
                                              ('session', owner, legacy)])
                    self.assertIs(owner._native_function_session, session)
                    selected.assert_called_once_with()
                    functions.session.assert_called_once_with(owner, legacy=legacy)
                    self.assertEqual(ours.initialize.call_count, int(route == 'admission'))
                    self.assertEqual(theirs.initialize.call_count, int(route == 'main'))

    def test_constructor_refusal_never_installs_a_function_session(self):
        for route in ('reference', 'admission', 'main'):
            for error in (HIAProgramRejected('original refusal', 'E_HIA_SCHEMA'), KeyboardInterrupt()):
                with self.subTest(route=route, exception=type(error).__name__), ExitStack() as stack:
                    owner, document = object.__new__(composite._Elaborator), object()

                    def initialize(instance, value, *, legacy=False):
                        instance.document = value
                        raise error

                    constructor = _RecordingOwner(initialize=Mock(side_effect=initialize))
                    stack.enter_context(patch.object(admission, 'selected_nominal_admission',
                        return_value=constructor if route == 'admission' else None))
                    stack.enter_context(patch.object(main_constructor, 'selected_composite_constructor',
                        return_value=constructor if route == 'main' else None))
                    stack.enter_context(patch.object(composite._Elaborator, '_reference_initialize',
                                                     new=initialize))
                    selected = stack.enter_context(patch.object(main_function, 'selected_composite_functions'))
                    try:
                        composite._Elaborator.__init__(owner, document)
                    except BaseException as actual:
                        self.assertIs(actual, error)
                    else:
                        self.fail('original constructor refusal was not preserved')
                    selected.assert_not_called()
                    self.assertEqual(vars(owner), {'document': document})

    def test_main_session_admission_refusal_does_not_fall_back(self):
        owner, document = object.__new__(composite._Elaborator), object()
        error = HIAProgramRejected('missing selected dependency', 'E_HIA_TYPE')

        def initialize(instance, value, *, legacy=False):
            instance.document = value

        selected = _RecordingOwner(session=Mock(side_effect=error))
        with patch.object(composite._Elaborator, '_reference_initialize', new=initialize), \
                patch.object(main_function, 'selected_composite_functions', return_value=selected), \
                patch.object(nominal_function, 'selected_nominal_function') as fallback:
            try:
                composite._Elaborator.__init__(owner, document)
            except HIAProgramRejected as actual:
                self.assertIs(actual, error)
            else:
                self.fail('session admission error was hidden')
            fallback.assert_not_called()
        selected.session.assert_called_once_with(owner, legacy=False)
        self.assertEqual(vars(owner), {'document': document})

    def test_admitted_main_session_remains_fixed_after_selector_clear_or_change(self):
        result = object()
        session = _RecordingOwner(function=Mock(return_value=result))
        functions = _RecordingOwner(session=Mock(return_value=session))
        with patch.dict(os.environ, {main_function.SELECTOR: 'recording-selected-owner'}), \
                patch.object(main_function, 'selected_composite_functions', return_value=functions) as admit:
            owner = composite._Elaborator(_document())
        admit.assert_called_once_with()
        functions.session.assert_called_once_with(owner, legacy=False)
        fn = owner.document['functions'][0]
        with patch.object(main_function, 'selected_composite_functions') as reselect, \
                patch.object(nominal_function, 'selected_nominal_function') as nominal, \
                patch.object(composite._Elaborator, '_reference_function') as reference, \
                patch.object(composite._Elaborator, '_reference_main_function') as main_reference:
            for path in ('', '/this-later-manifest-must-not-be-selected'):
                with self.subTest(path=path), patch.dict(os.environ, {main_function.SELECTOR: path}):
                    self.assertIs(owner.function(fn), result)
            for callback in (reselect, nominal, reference, main_reference):
                callback.assert_not_called()
        self.assertEqual(session.function.call_count, 2)
        self.assertIs(owner._native_function_session, session)

    def test_fixed_main_session_refuses_a_new_nominal_function_selector(self):
        owner = composite._Elaborator(_document())
        owner._native_function_session = _RecordingOwner(function=Mock())
        with patch.dict(os.environ, {nominal_function.SELECTOR: 'nominal-owner'}), \
                patch.object(nominal_function, 'selected_nominal_function') as selected:
            self.assert_refusal(lambda: owner.function(owner.document['functions'][0]),
                                'conflicting native function owners')
            selected.assert_not_called()
            owner._native_function_session.function.assert_not_called()

    def test_late_main_function_selector_without_admission_refuses(self):
        owner = composite._Elaborator(_document())
        with patch.dict(os.environ, {main_function.SELECTOR: 'late-owner'}), \
                patch.object(main_function, 'selected_composite_functions') as reselect, \
                patch.object(nominal_function, 'selected_nominal_function') as nominal, \
                patch.object(composite._Elaborator, '_reference_function') as reference:
            self.assert_refusal(lambda: owner.function(owner.document['functions'][0]),
                                'session was not admitted by this constructor')
            for callback in (reselect, nominal, reference):
                callback.assert_not_called()

    def test_nominal_function_route_and_its_reference_remain_distinct(self):
        owner, fn = object.__new__(composite._Elaborator), object()
        result = object()
        native = _RecordingOwner(lower=Mock(return_value=result))
        with patch.object(main_function, 'selected_composite_functions') as other_selector, \
                patch.object(nominal_function, 'selected_nominal_function', return_value=native) as selected, \
                patch.object(composite._Elaborator, '_reference_function', return_value=result) as reference, \
                patch.object(composite._Elaborator, '_reference_main_function') as other_reference:
            self.assertIs(owner.function(fn), result)
            native.lower.assert_called_once_with(owner, fn)
            reference.assert_not_called()
            selected.return_value = None
            self.assertIs(owner.function(fn), result)
            reference.assert_called_once_with(fn)
            self.assertEqual(selected.call_count, 2)
            other_selector.assert_not_called()
            other_reference.assert_not_called()

    def test_main_outer_rejects_nominal_function_abi_before_any_native_entry(self):
        # This invokes the real ABI admission, with deliberately non-executable
        # image sentinels. It does not qualify either native implementation.
        entries = {name: _RecordingOwner(_entry=Mock()) for name in main_outer.KERNELS}
        outer = main_outer.NativeCompositeOuter(entries,
            types_source_sha256=sha256(main_outer.TYPE_SOURCE.read_bytes()).hexdigest(),
            helpers_source_sha256=sha256(main_outer.HELPER_SOURCE.read_bytes()).hexdigest(),
            function_sources_sha256={name: sha256(path.read_bytes()).hexdigest()
                                     for name, path in main_outer.FUNCTION_SOURCES.items()})
        owner = object.__new__(composite._Elaborator)
        owner.native_types = None
        owner._native_function_session = nominal_function.FunctionContext.__new__(nominal_function.FunctionContext)
        with patch.dict(os.environ, {main_outer.SELECTOR: 'recording-outer',
                                    nominal_function.SELECTOR: 'recording-nominal-function'}), \
                patch.object(main_outer, 'selected_composite_outer', return_value=outer), \
                patch.object(nominal_module, 'selected_nominal_module', return_value=None), \
                patch.object(nominal_function, 'selected_nominal_function') as selected, \
                patch.object(ctypes, 'create_string_buffer') as allocate:
            self.assert_refusal(owner.lower, 'requires the complete native function/type session')
            allocate.assert_not_called()
            selected.assert_not_called()
            for image in entries.values():
                image._entry.assert_not_called()

    def test_module_routes_dispatch_their_own_owner_only(self):
        for route in ('reference', 'nominal', 'main'):
            with self.subTest(route=route):
                owner, result = object.__new__(composite._Elaborator), object()
                ours = _RecordingOwner(lower=Mock(return_value=result))
                theirs = _RecordingOwner(lower=Mock(return_value=result))
                with patch.object(nominal_module, 'selected_nominal_module',
                                  return_value=ours if route == 'nominal' else None), \
                        patch.object(main_outer, 'selected_composite_outer',
                                     return_value=theirs if route == 'main' else None), \
                        patch.object(composite._Elaborator, '_reference_lower', return_value=result) as reference:
                    self.assertIs(owner.lower(), result)
                    self.assertEqual(ours.lower.call_count, int(route == 'nominal'))
                    self.assertEqual(theirs.lower.call_count, int(route == 'main'))
                    self.assertEqual(reference.call_count, int(route == 'reference'))

    def test_nonempty_missing_main_manifests_never_select_reference_success(self):
        with tempfile.TemporaryDirectory(prefix='hia-route-refusal-') as temporary:
            missing = str(Path(temporary) / 'missing.json')
            for selector in (main_constructor.SELECTOR, main_function.SELECTOR, main_outer.SELECTOR):
                with self.subTest(selector=selector), patch.dict(os.environ, {selector: missing}):
                    self.assert_refusal(lambda: composite.elaborate_program(_document()),
                                        'selected native composite')
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_public_facade_closes_both_sessions_with_result_or_exception_held(self):
        for error in (None, HIAProgramRejected('lower refusal', 'E_HIA_TYPE'), KeyboardInterrupt()):
            with self.subTest(exception=None if error is None else type(error).__name__):
                types, session, buffers = _transport_sessions()
                events, owners, result = [], [], object()
                function_close, type_close = session.close, types.close

                def initialize(owner, document, *, legacy=False):
                    owners.append(owner)
                    owner.native_types, owner._native_function_session = types, session

                def close_function():
                    events.append('function')
                    function_close()

                def close_types():
                    events.append('types')
                    type_close()

                with patch.object(composite._Elaborator, '__init__', new=initialize), \
                        patch.object(composite._Elaborator, 'lower', side_effect=error,
                                     return_value=result), \
                        patch.object(session, 'close', side_effect=close_function), \
                        patch.object(types, 'close', side_effect=close_types):
                    held = None
                    try:
                        actual = composite.elaborate_program(_document())
                    except BaseException as caught:
                        self.assertIs(caught, error)
                        held = caught
                    else:
                        self.assertIsNone(error)
                        self.assertIs(actual, result)
                    if error is not None:
                        self.assertIs(held, error)
                        self.assertIsNotNone(held.__traceback__)
                    self.assertEqual(events, ['function', 'types'])
                    self.assertTrue(session._closed)
                    self.assertTrue(types._closed)
                    self.assertTrue(all(reference() is None for reference in buffers))
                    self.assertEqual(len(owners), 1)
                    self.assertIs(owners[0].native_types, types)

    def test_public_constructor_failure_closes_only_published_sessions(self):
        for include_function in (False, True):
            with self.subTest(function_published=include_function):
                types, session, buffers = _transport_sessions(function=include_function)
                error = KeyboardInterrupt('constructor interrupted after publication')
                owners = []

                def initialize(owner, document, *, legacy=False):
                    owners.append(owner)
                    owner.document, owner.native_types = document, types
                    if include_function:
                        owner._native_function_session = session
                    raise error

                with patch.object(composite._Elaborator, '__init__', new=initialize), \
                        patch.object(composite._Elaborator, 'lower') as lower:
                    try:
                        composite.elaborate_program(_document())
                    except BaseException as caught:
                        self.assertIs(caught, error)
                        self.assertIsNotNone(caught.__traceback__)
                        self.assertTrue(all(reference() is None for reference in buffers))
                    else:
                        self.fail('constructor interruption was not propagated')
                    lower.assert_not_called()
                self.assertTrue(types._closed)
                self.assertEqual('_native_function_session' in vars(owners[0]), include_function)
                if include_function:
                    self.assertTrue(session._closed)

    def test_function_close_failure_still_closes_the_type_session(self):
        types, _, buffers = _transport_sessions(function=False)
        error = RuntimeError('injected function-close failure')
        function = _RecordingOwner(close=Mock(side_effect=error))

        def initialize(owner, document, *, legacy=False):
            owner.native_types, owner._native_function_session = types, function

        with patch.object(composite._Elaborator, '__init__', new=initialize), \
                patch.object(composite._Elaborator, 'lower', return_value={}):
            try:
                composite.elaborate_program(_document())
            except RuntimeError as caught:
                self.assertIs(caught, error)
                self.assertIsNotNone(caught.__traceback__)
                self.assertTrue(all(reference() is None for reference in buffers))
            else:
                self.fail('injected close error was hidden')
        function.close.assert_called_once_with()
        self.assertTrue(types._closed)


if __name__ == '__main__':
    unittest.main()
