"""Original VM controls for the explicit arithmetic-membership preparation.

The three existing prepared-VM test bodies and observer bodies are invoked
unchanged with only their candidate construction bindings redirected. The old
module and every old test remain byte-identical. This file adds separate tests;
it does not replace any old gate or relax any old VM budget.
"""
from __future__ import annotations

import ast
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
from types import FunctionType, MappingProxyType
import unittest

from hepta import hia_program_runtime as runtime
from hepta import hia_program_runtime_prepared as prepared_module
from hepta import hia_program_runtime_arithmetic as arithmetic_module
from hepta.hia_program import VerifiedProgram, verify_program
from tests import test_hia_program_runtime_prepared as original

_ORIGINAL_TEST_SHA256 = 'ce78a3faac842b6447c390fa2da9ebbceb635a1b60f54decc97d89eb9bb2110b'
_RUNTIME_SHA256 = 'ce39be78627f253447f1d4e4b3272ba6689c594c31b22e3be204b1fcfea2ca56'
_PREPARED_SHA256 = '21a5d3f8dd32949448f0d3f05633e11b75abf849ed125414a858aa0f85fd8188'
_LIMITS = original._LIMITS


def _function(function, namespace):
    result = FunctionType(function.__code__, namespace, function.__name__,
                          function.__defaults__, function.__closure__)
    result.__kwdefaults__ = function.__kwdefaults__
    return result


def _observe(factory, program, function, arguments, limits=_LIMITS):
    namespace = dict(original._observe.__globals__)
    namespace['_Machine'] = factory
    return _function(original._observe, namespace)(program, function, arguments, limits)


class _Routes:
    """Only inject a candidate factory; expected calls keep the original VM."""
    def __init__(self):
        self.entries = []
        self.prepared = 0
        self.optimized_machines = 0

    def prepare(self, program):
        value, factory = arithmetic_module.prepare_arithmetic_runtime(program)
        if factory is not runtime._Machine:
            self.entries.append((value, factory))
            self.prepared += 1
        return value

    def machine(self, program, *limits):
        factory = runtime._Machine
        for value, candidate_factory in reversed(self.entries):
            if value is program:
                factory = candidate_factory
                break
        result = factory(program, *limits)
        if (type(result) is arithmetic_module._PreparedMachine
                and result._arithmetic_active):
            self.optimized_machines += 1
        return result

    def invoke_original_test(self, name, case):
        method = vars(original.PreparedRuntimeSourceTests)[name]
        namespace = dict(method.__globals__)
        namespace['prepare_runtime_program'] = self.prepare
        namespace['_Machine'] = self.machine
        namespace['_observe'] = _function(original._observe, namespace)
        namespace['_observe_borrowed'] = _function(original._observe_borrowed, namespace)
        _function(method, namespace)(case)


class _PrivateInstruction:
    def __init__(self, values, events):
        self.values, self.events = values, events

    def __getitem__(self, key):
        self.events.append(('item', key))
        return self.values[key]


class _PrivateOpcode(str):
    def __new__(cls, value, events, fault=None):
        result = str.__new__(cls, value)
        result.events, result.fault = events, fault
        return result

    def __eq__(self, other):
        self.events.append(('equal', other))
        return str.__eq__(self, other)

    def __hash__(self):
        self.events.append(('hash', str(self)))
        if self.fault is not None:
            raise self.fault
        return str.__hash__(self)

    def split(self, *args, **kwargs):
        self.events.append(('split', args, tuple(kwargs.items())))
        return str.split(self, *args, **kwargs)

    def endswith(self, *args, **kwargs):
        self.events.append(('endswith', args, tuple(kwargs.items())))
        return str.endswith(self, *args, **kwargs)


def _private_instruction_observation(factory, program, fault):
    machine = factory(program, *_LIMITS)
    function = machine.functions['calculate']
    source = function['blocks'][0]['ops'][0]
    events = []
    values = dict(source)
    values['op'] = _PrivateOpcode('int.add.checked', events, fault)
    instruction = _PrivateInstruction(values, events)
    environment = {param['name']: value for param, value in zip(function['params'], (2, 3))}
    try:
        result = machine.operation(instruction, environment, 0)
    except BaseException as error:
        outcome = ('error', type(error), error.args, error is fault)
    else:
        outcome = ('return', result)
    return {'events': events, 'outcome': outcome, 'environment': environment,
            'machine': original._machine_state(machine)}


class ArithmeticPreparedRuntimeSourceTests(unittest.TestCase):
    def setUp(self):
        self.selector_before = os.environ.pop(original._SELECTOR, original._MISSING)
        self.assertEqual(sha256(Path(original.__file__).read_bytes()).hexdigest(),
                         _ORIGINAL_TEST_SHA256)
        actual_runtime = Path(runtime.__file__).read_bytes()
        retained_runtime = arithmetic_module._retained_runtime_source(actual_runtime)
        self.assertEqual(sha256(retained_runtime).hexdigest(), _RUNTIME_SHA256)
        self.assertEqual(sha256(Path(prepared_module.__file__).read_bytes()).hexdigest(),
                         _PREPARED_SHA256)

    def tearDown(self):
        if self.selector_before is original._MISSING:
            os.environ.pop(original._SELECTOR, None)
        else:
            os.environ[original._SELECTOR] = self.selector_before

    def _original(self, name):
        routes = _Routes()
        routes.invoke_original_test(name, self)
        self.assertGreater(routes.prepared, 0)
        self.assertGreater(routes.optimized_machines, 0)
        return routes

    def test_original_49_semantics_reports_and_stopped_storage(self):
        routes = self._original('test_default_execution_reports_and_stopped_storage_match')
        # The unchanged method contains 47 ordinary cases and 2 whole-buffer
        # borrowed cases. Its 48 preparation calls are actually observed.
        self.assertEqual(routes.prepared, 48)
        self.assertEqual(routes.optimized_machines, 49)

    def test_original_readonly_snapshot_and_fresh_entry_state(self):
        self._original('test_readonly_snapshot_and_fresh_entry_state')

    def test_original_complete_dynamic_bytes_decoder_selector_fallback(self):
        self._original('test_changed_bytes_bindings_selectors_and_custom_providers_use_original')

    def test_all_six_arithmetic_members_and_actual_derived_operation(self):
        count = 0
        for typ in ('i8', 'u8', 'i16', 'u16', 'i32', 'u32',
                    'i64', 'u64', 'isize', 'usize'):
            lo, hi = original.program_module.integer_range(typ)
            for opcode in arithmetic_module._ARITHMETIC:
                for arguments in ((lo, 1), (hi, 1), (hi, 2)):
                    with self.subTest(type=typ, opcode=opcode, arguments=arguments):
                        checked = verify_program(original.arithmetic(opcode, typ))
                        expected = original._observe(checked, 'calculate', arguments)
                        prepared, factory = arithmetic_module.prepare_arithmetic_runtime(checked)
                        self.assertIsNot(factory, runtime._Machine)
                        self.assertEqual(_observe(factory, prepared, 'calculate', arguments),
                                         expected)
                        count += 1
        self.assertEqual(count, 180)
        checked = verify_program(original.arithmetic('int.add.wrap'))
        prepared, factory = arithmetic_module.prepare_arithmetic_runtime(checked)
        authority = factory._authority
        original_wrap = runtime._wrap
        calls = []

        def wrap(value, typ):
            # The current code object, not a function name or counter, proves
            # which real operation reached this unchanged dynamic primitive.
            calls.append((sys._getframe(1).f_code, value, typ))
            return original_wrap(value, typ)

        with original._Attribute(runtime, '_wrap', wrap):
            expected = original._observe(checked, 'calculate', (2, 3))
            baseline_calls = tuple(calls)
            calls.clear()
            actual = _observe(factory, prepared, 'calculate', (2, 3))
            candidate_calls = tuple(calls)
        self.assertEqual(actual, expected)
        self.assertTrue(baseline_calls)
        self.assertEqual([(a, b) for _, a, b in candidate_calls],
                         [(a, b) for _, a, b in baseline_calls])
        self.assertTrue(all(code is arithmetic_module._OPERATION.__code__
                            for code, _, _ in baseline_calls))
        self.assertTrue(all(code is authority.operation.__code__
                            for code, _, _ in candidate_calls))
        self.assertIsNot(authority.operation.__code__, arithmetic_module._OPERATION.__code__)

    def test_private_opcode_instruction_and_metadata_keep_original_path(self):
        checked = verify_program(original.arithmetic())
        prepared, factory = arithmetic_module.prepare_arithmetic_runtime(checked)
        for fault in (None, MemoryError('private opcode hash')):
            with self.subTest(fault=type(fault).__name__):
                expected = _private_instruction_observation(runtime._Machine, checked, fault)
                actual = _private_instruction_observation(factory, prepared, fault)
                self.assertEqual(actual, expected)
                if fault is not None:
                    self.assertTrue(actual['outcome'][-1])
        document = checked.as_dict()
        custom = original._CustomProgram(document)
        value, custom_factory = arithmetic_module.prepare_arithmetic_runtime(custom)
        self.assertIs(value, custom)
        self.assertIs(custom_factory, runtime._Machine)
        self.assertEqual(custom.calls, [])
        derived = original._DerivedProgram(checked.canonical_bytes)
        value, derived_factory = arithmetic_module.prepare_arithmetic_runtime(derived)
        self.assertIs(value, derived)
        self.assertIs(derived_factory, runtime._Machine)

        # A private wrapper with even valid ordinary-looking metadata is not a
        # receipt from this preparation call and cannot activate its fast path.
        forged = prepared_module._PreparedRuntimeProgram(
            checked, checked.canonical_bytes, checked.structured_bytes, document)
        value, forged_factory = arithmetic_module.prepare_arithmetic_runtime(forged)
        self.assertIs(value, forged)
        self.assertIs(forged_factory, runtime._Machine)
        self.assertEqual(_observe(forged_factory, value, 'calculate', (2, 3)),
                         original._observe(forged, 'calculate', (2, 3)))

        # Exact VerifiedProgram can be constructed privately, without verifier
        # admission. Non-string opcodes and incomplete shapes are not rejected
        # early by the optimization: preserve the original constructor/op error.
        documents = [
            {}, {'functions': None}, {'functions': [None]},
            {'functions': [{'name': 'calculate', 'blocks': None}]},
        ]
        malformed = checked.as_dict()
        malformed['functions'][0]['blocks'][0]['ops'][0]['op'] = 17
        documents.append(malformed)
        for document in documents:
            with self.subTest(private_document=document):
                raw = VerifiedProgram(json.dumps(document, separators=(',', ':')).encode())
                value, rejected_factory = arithmetic_module.prepare_arithmetic_runtime(raw)
                self.assertIs(rejected_factory, runtime._Machine)
                outcomes = []
                self.assertIs(value, raw)
                for program in (raw, value):
                    try:
                        machine = runtime._Machine(program, *_LIMITS)
                        result = machine.invoke(machine.functions['calculate'], [2, 3])
                    except BaseException as error:
                        outcomes.append(('error', type(error), error.args,
                                         getattr(error, 'code', None)))
                    else:
                        outcomes.append(('returned', result, original._machine_state(machine)))
                self.assertEqual(outcomes[0], outcomes[1])

    def test_changed_metadata_and_machine_bindings_preserve_real_fallback(self):
        checked = verify_program(original.arithmetic())
        prepared, factory = arithmetic_module.prepare_arithmetic_runtime(checked)
        original_document = object.__getattribute__(prepared, '_document')
        changed = verify_program(original.arithmetic('int.mul.checked'))
        replacement_document = prepared_module._freeze(changed.as_dict())
        try:
            object.__setattr__(prepared, '_document', replacement_document)
            expected = original._observe(prepared, 'calculate', (2, 3))
            machine = factory(prepared, *_LIMITS)
            self.assertIs(type(machine), runtime._Machine)
            self.assertEqual(_observe(factory, prepared, 'calculate', (2, 3)), expected)
            self.assertEqual(expected['report']['result'], 6)
        finally:
            object.__setattr__(prepared, '_document', original_document)
        self.assertEqual(_observe(factory, prepared, 'calculate', (2, 3))['report']['result'], 5)

        for name in ('__init__', 'invoke', 'operation'):
            old = vars(runtime._Machine)[name]
            calls = []

            def replacement(self, *args, **kwargs):
                calls.append(name)
                return old(self, *args, **kwargs)

            with self.subTest(machine_binding=name):
                with original._Attribute(runtime._Machine, name, replacement):
                    value, direct_factory = arithmetic_module.prepare_arithmetic_runtime(checked)
                    self.assertIs(value, checked)
                    self.assertIs(direct_factory, runtime._Machine)
                    expected = original._observe(checked, 'calculate', (2, 3))
                    calls.clear()
                    self.assertEqual(_observe(factory, prepared, 'calculate', (2, 3)), expected)
                    self.assertTrue(calls)
                    machine = factory(prepared, *_LIMITS)
                    self.assertIs(type(machine), runtime._Machine)

        # Replacement after Machine creation follows the actual base descriptor
        # through super(), instead of calling a captured old strategy.
        machine = factory(prepared, *_LIMITS)
        old = vars(runtime._Machine)['operation']
        calls = []

        def replacement(self, instruction, environment, depth):
            calls.append(instruction['op'])
            return old(self, instruction, environment, depth)

        with original._Attribute(runtime._Machine, 'operation', replacement):
            expected = original._observe(checked, 'calculate', (2, 3))
            expected_calls = tuple(calls)
            calls.clear()
            values = machine.invoke(machine.functions['calculate'], [2, 3])
            actual = {'exception': None, 'report': machine.report('calculate', 'returned', values),
                      'machine': original._machine_state(machine)}
            self.assertEqual(actual, expected)
            self.assertEqual(tuple(calls), expected_calls)

        for name in ('prepare_runtime_program', '_ordinary_default_program', '_freeze'):
            old = vars(prepared_module)[name]

            def replacement(*args, **kwargs):
                return old(*args, **kwargs)

            with self.subTest(helper_binding=name):
                with original._Attribute(prepared_module, name, replacement):
                    value, direct_factory = arithmetic_module.prepare_arithmetic_runtime(checked)
                    self.assertIs(value, checked)
                    self.assertIs(direct_factory, runtime._Machine)
                    self.assertIs(type(factory(prepared, *_LIMITS)), runtime._Machine)

    def test_source_code_custody_and_explicit_host_failure_boundary(self):
        checked = verify_program(original.arithmetic())
        prepared, factory = arithmetic_module.prepare_arithmetic_runtime(checked)
        self.assertIsNot(factory, runtime._Machine)
        derived = factory._authority.operation
        original_code = arithmetic_module._OPERATION.__code__
        self.assertIs(derived.__globals__, arithmetic_module._OPERATION.__globals__)
        self.assertEqual(derived.__defaults__, arithmetic_module._OPERATION.__defaults__)
        self.assertEqual(derived.__closure__, arithmetic_module._OPERATION.__closure__)
        self.assertNotEqual(derived.__code__.co_code, original_code.co_code)
        self.assertEqual(derived.__code__.co_names, original_code.co_names)

        tree = ast.parse(Path(runtime.__file__).read_bytes())
        cls = next(node for node in tree.body if isinstance(node, ast.ClassDef)
                   and node.name == '_Machine')
        operation = next(node for node in cls.body if isinstance(node, ast.FunctionDef)
                         and node.name == 'operation')
        target = ast.parse(
            '{f"int.{a}.{m}" for a in ("add", "sub", "mul") for m in ("checked", "wrap")}',
            mode='eval').body
        matches = [node for node in ast.walk(operation) if isinstance(node, ast.SetComp)
                   and ast.dump(node, include_attributes=False)
                       == ast.dump(target, include_attributes=False)]
        self.assertEqual(len(matches), 1)
        self.assertEqual(set(arithmetic_module._ARITHMETIC),
                         {'int.add.checked', 'int.add.wrap', 'int.sub.checked',
                          'int.sub.wrap', 'int.mul.checked', 'int.mul.wrap'})

        # A populated derived-code cache cannot bypass the source check at the
        # next preparation boundary. These do not mutate actual source files.
        self.assertIsNot(arithmetic_module._CACHE, None)
        for name in ('_RUNTIME_SHA256', '_PREPARED_SHA256'):
            with self.subTest(source_binding=name):
                with original._Attribute(arithmetic_module, name, '0' * 64):
                    value, denied = arithmetic_module.prepare_arithmetic_runtime(checked)
                    self.assertIs(value, checked)
                    self.assertIs(denied, runtime._Machine)
        old_cache = arithmetic_module._CACHE
        fault = MemoryError('controlled preparation compiler allocation')
        calls = []

        def fail_compile(*args, **kwargs):
            calls.append(args[0])
            raise fault

        try:
            arithmetic_module._CACHE = None
            with original._Attribute(arithmetic_module, 'compile', fail_compile):
                with self.assertRaises(MemoryError) as caught:
                    arithmetic_module.prepare_arithmetic_runtime(checked)
                self.assertIs(caught.exception, fault)
                self.assertIsNone(arithmetic_module._CACHE)
                self.assertEqual(len(calls), 1)
        finally:
            arithmetic_module._CACHE = old_cache
        self.assertEqual(_observe(factory, prepared, 'calculate', (2, 3)),
                         original._observe(checked, 'calculate', (2, 3)))


        # Existing factories and already constructed Machines must not execute
        # a changed derived target, even while both source files and the old
        # runtime method remain exact. Test realistic writable FunctionType
        # fields and replacement of the held target/cache separately.
        authority = factory._authority
        derived = authority.operation

        def forbidden(self, instruction, environment, depth):
            raise AssertionError('changed derived execution target was called')

        replacement_globals = dict(derived.__globals__)
        replacement_target = FunctionType(derived.__code__, replacement_globals)
        for label, owner, field, replacement, invalidates_cache in (
            ('code', derived, '__code__', forbidden.__code__, True),
            ('defaults', derived, '__defaults__', ('changed-default',), True),
            ('kwdefaults', derived, '__kwdefaults__', {'changed': True}, True),
            ('authority-target', authority, 'operation', forbidden, False),
            ('authority-globals-target', authority, 'operation', replacement_target, False),
            ('cache-target', arithmetic_module, '_CACHE', forbidden, True),
        ):
            with self.subTest(live_derived_change=label):
                existing = factory(prepared, *_LIMITS)
                self.assertIs(type(existing), arithmetic_module._PreparedMachine)
                original_checked = runtime._checked
                calls = []

                def checked_primitive(value, typ):
                    calls.append(sys._getframe(1).f_code)
                    return original_checked(value, typ)

                with original._Attribute(owner, field, replacement):
                    if invalidates_cache:
                        rejected_program, rejected_factory = (
                            arithmetic_module.prepare_arithmetic_runtime(checked))
                        self.assertIs(rejected_program, checked)
                        self.assertIs(rejected_factory, runtime._Machine)
                    self.assertIs(type(factory(prepared, *_LIMITS)), runtime._Machine)
                    with original._Attribute(runtime, '_checked', checked_primitive):
                        expected = original._observe(checked, 'calculate', (2, 3))
                        baseline_codes = tuple(calls)
                        calls.clear()
                        result = existing.invoke(existing.functions['calculate'], [2, 3])
                        actual = {'exception': None,
                            'report': existing.report('calculate', 'returned', result),
                            'machine': original._machine_state(existing)}
                    self.assertEqual(actual, expected)
                    self.assertTrue(baseline_codes)
                    self.assertEqual(tuple(calls), baseline_codes)
                    self.assertTrue(all(code is arithmetic_module._OPERATION.__code__
                                        for code in calls))
                self.assertTrue(arithmetic_module._derived_current(
                    authority.operation, authority.operation_stamp))


    def test_exact_runtime_source_successor_and_populated_cache_refuse_unlisted_bytes(self):
        raw = Path(runtime.__file__).read_bytes()
        self.assertEqual(sha256(raw).hexdigest(),
                         'db118314608168799a0d2c1210cec04ba38981a329e8da6cf4debcd07b267aa0')
        retained = arithmetic_module._retained_runtime_source(raw)
        self.assertEqual(sha256(retained).hexdigest(), _RUNTIME_SHA256)
        self.assertEqual(arithmetic_module._retained_runtime_source(retained), retained)
        self.assertNotEqual(retained, raw)
        checked = verify_program(original.arithmetic())
        prepared, factory = arithmetic_module.prepare_arithmetic_runtime(checked)
        self.assertIsNot(factory, runtime._Machine)
        self.assertEqual(factory._authority.operation_stamp[6], sha256(raw).hexdigest())
        self.assertEqual(len(factory._authority.operation_stamp), 7)
        for invalid in (bytearray(raw), raw.decode(), raw + b'\n',
                        raw.replace(b'8 > extent - index', b'7 > extent - index', 1)):
            with self.subTest(invalid_type=type(invalid).__name__), self.assertRaises(ValueError):
                arithmetic_module._retained_runtime_source(invalid)
        target = Path(runtime.__file__)
        original_read = Path.read_bytes
        # The second exact source also requires its own compiled-code proof;
        # an existing v9 cache cannot be reused for a purported old v8 file.
        for substituted in (raw + b'\n', retained):
            def read(path):
                return substituted if path == target else original_read(path)
            with original._Attribute(Path, 'read_bytes', read):
                value, rejected = arithmetic_module.prepare_arithmetic_runtime(checked)
                self.assertIs(value, checked)
                self.assertIs(rejected, runtime._Machine)
        stamp = arithmetic_module._CACHE
        for digest in ('0' * 64, True, b'invalid'):
            with original._Attribute(arithmetic_module, '_CACHE', (*stamp[:6], digest)):
                value, rejected = arithmetic_module.prepare_arithmetic_runtime(checked)
                self.assertIs(value, checked)
                self.assertIs(rejected, runtime._Machine)
                self.assertIs(type(factory(prepared, *_LIMITS)), runtime._Machine)
        self.assertIs(arithmetic_module._CACHE, stamp)

    def test_exact_v9_word_order_sources_and_changed_live_mappings_refuse_preparation(self):
        raw = Path(runtime.__file__).read_bytes()
        state = arithmetic_module._word_order_state(raw)
        self.assertEqual(tuple(name for name, _, _ in state), ('WORD_LOADS', 'WORD_STORES'))
        checked = verify_program(original.arithmetic())
        for name, mapping, items in state:
            self.assertIs(type(mapping), MappingProxyType)
            self.assertEqual(tuple(mapping.items()), items)
            changed = dict(items)
            first = next(iter(changed))
            changed[first] = 'big' if changed[first] == 'little' else 'little'
            for replacement in (dict(items), MappingProxyType(changed),
                                MappingProxyType(dict(reversed(items)))):
                with self.subTest(binding=name, type=type(replacement).__name__):
                    with original._Attribute(runtime, name, replacement):
                        with self.assertRaises(ValueError):
                            arithmetic_module._word_order_state(raw)
                        value, rejected = arithmetic_module.prepare_arithmetic_runtime(checked)
                        self.assertIs(value, checked)
                        self.assertIs(rejected, runtime._Machine)
        self.assertEqual(arithmetic_module._word_order_state(
            arithmetic_module._retained_runtime_source(raw)), ())

    def test_all_v9_word_operations_keep_full_original_reports_and_stopped_storage(self):
        from tools.hia_word_memory_cases import owned_program
        checked = verify_program(owned_program())
        prepared, factory = arithmetic_module.prepare_arithmetic_runtime(checked)
        self.assertIsNot(factory, runtime._Machine)
        count = 0
        for order in ('le', 'be'):
            for mode in ('load', 'store'):
                for length, offset in ((0, 0), (7, 0), (8, 0), (9, 1), (17, 9),
                                       (17, 10), (17, (1 << 32) + 1), (17, (1 << 64) - 1)):
                    for value in (0, 0x0123456789ABCDEF, (1 << 64) - 1):
                        with self.subTest(order=order, mode=mode, length=length, offset=offset, value=value):
                            arguments = (length, offset, value, 0)
                            name = mode + '_' + order
                            expected = original._observe(checked, name, arguments)
                            self.assertEqual(_observe(factory, prepared, name, arguments), expected)
                            machine = factory(prepared, *_LIMITS)
                            self.assertIs(type(machine), arithmetic_module._PreparedMachine)
                            self.assertTrue(machine._arithmetic_active)
                            count += 1
        self.assertEqual(count, 96)


if __name__ == '__main__':
    unittest.main()
