"""Independent old-VM/prepared-VM semantics and metadata admission controls."""
from __future__ import annotations

import os
import sys
from types import ModuleType
import unittest

from hepta import hia_json_decode as decoder_module
from hepta import hia_program as program_module
from hepta.hia_program import VerifiedProgram, verify_program
from hepta.hia_program_runtime import (
    HIAProgramBudgetExceeded, HIAProgramTrap, _Machine, _Owner, _View,
)
from hepta.hia_program_runtime_prepared import prepare_runtime_program
from tests.test_hia_program import (
    arithmetic, b, c, f, i, joined_loan_program, jump, m,
    resource_program, ret,
)

_SELECTOR = 'HEPTA_HIA_JSON_DECODE_MANIFEST'
_MISSING = object()
_LIMITS = (4_000_000, 16 << 20, None, 128)


class _Attribute:
    def __init__(self, obj, name, value):
        self.obj, self.name, self.value = obj, name, value

    def __enter__(self):
        self.before = getattr(self.obj, self.name, _MISSING)
        setattr(self.obj, self.name, self.value)
        return self

    def __exit__(self, *unused):
        if self.before is _MISSING:
            delattr(self.obj, self.name)
        else:
            setattr(self.obj, self.name, self.before)


class _DictionaryEntry:
    def __init__(self, mapping, key, value):
        self.mapping, self.key, self.value = mapping, key, value

    def __enter__(self):
        self.before = self.mapping.get(self.key, _MISSING)
        self.mapping[self.key] = self.value
        return self

    def __exit__(self, *unused):
        if self.before is _MISSING:
            self.mapping.pop(self.key, None)
        else:
            self.mapping[self.key] = self.before


class _MethodReplacement:
    def __init__(self, document, error=None):
        self.document, self.error, self.calls = document, error, []

    def __call__(self):
        self.calls.append('as_dict')
        if self.error is not None:
            raise self.error
        return self.document


class _ProgramFieldReplacement:
    def __init__(self, name, value, error=None):
        self.name, self.value, self.error, self.calls = name, value, error, []

    def __get__(self, instance, owner):
        if instance is None:
            return self
        self.calls.append(self.name)
        if self.error is not None:
            raise self.error
        return self.value


class _DecodeReplacement:
    def __init__(self, document, error=None):
        self.document, self.error, self.calls = document, error, []

    def __call__(self, wire, **limits):
        self.calls.append((wire, dict(limits)))
        if self.error is not None:
            raise self.error
        return self.document


class _SelectedDecoder:
    def __init__(self, document):
        self.document, self.calls = document, []

    def __call__(self, manifest):
        self.calls.append(('installed_decoder', manifest))
        return self

    def decode(self, wire, **limits):
        self.calls.append(('decode', wire, dict(limits)))
        return self.document


class _ScanReplacement:
    def __init__(self, document):
        self.document, self.calls = document, []

    def __call__(self, text, index):
        self.calls.append((text, index))
        return self.document, len(text)


class _EncodingReplacement:
    def __init__(self):
        self.calls = []

    def __call__(self, wire):
        self.calls.append(wire)
        return 'utf-8'


class _CustomProgram:
    def __init__(self, document):
        self.document, self.calls = document, []

    def as_dict(self):
        self.calls.append('custom_as_dict')
        return self.document


class _DerivedProgram(VerifiedProgram):
    pass


def _machine_state(machine):
    return {
        'limits': (machine.max_steps, machine.max_heap_bytes,
                   machine.allocation_fail_at, machine.max_call_depth),
        'steps': machine.steps,
        'resources': machine.resources(),
        'owners': tuple((key, owner.ident, bytes(owner.data), owner.active)
                        for key, owner in machine.owners.items()),
        'chains': tuple((key, chain.ident, chain.active)
                        for key, chain in machine.chains.items()),
        'function_names': tuple(machine.functions),
    }


def _observe(program, name, arguments, limits=_LIMITS):
    # A trap snapshot describes actual stopped resources, without fake cleanup.
    machine = _Machine(program, *limits)
    try:
        values = machine.invoke(machine.functions[name], list(arguments))
    except (HIAProgramTrap, HIAProgramBudgetExceeded) as error:
        status = 'trapped' if type(error) is HIAProgramTrap else 'budget_exceeded'
        result = {'exception': (type(error).__module__, type(error).__qualname__,
                                error.code, error.args),
                  'report': machine.report(name, status, error=error)}
    else:
        result = {'exception': None,
                  'report': machine.report(name, 'returned', values)}
    result['machine'] = _machine_state(machine)
    return result


def _borrowed_program():
    return m(f('borrowed', [('source', 'readbuf'), ('output', 'mutbuf'),
                           ('state', 'mutbuf')], ['u8'], ['read', 'write', 'trap'], [
        b('entry', [('source', 'readbuf'), ('output', 'mutbuf'), ('state', 'mutbuf')], [
            c('zero', 'usize', 0), c('one', 'usize', 1),
            i('buffer.load', ['source', 'zero'], [('value', 'u8')]),
            i('buffer.store', ['output', 'zero', 'value']),
            i('buffer.store', ['state', 'one', 'value']),
        ], ret('value')),
    ]))


def _observe_borrowed(program, value):
    owners = (_Owner(-1, bytearray((value, 32, 33))),
              _Owner(-2, bytearray((40, 41, 42, 43))),
              _Owner(-3, bytearray((50, 51, 52, 53, 54))))
    views = tuple(_View(owner, index != 0) for index, owner in enumerate(owners))
    machine = _Machine(program, *_LIMITS)
    values = machine.invoke(machine.functions['borrowed'], list(views))
    return {
        'report': machine.report('borrowed', 'returned', values, external_roots=owners),
        'machine': _machine_state(machine),
        'whole_external_buffers': tuple(bytes(owner.data) for owner in owners),
        'owner_active': tuple(owner.active for owner in owners),
        'view_active': tuple(view.active for view in views),
        'view_mutable': tuple(view.mutable for view in views),
    }


class PreparedRuntimeSourceTests(unittest.TestCase):
    def setUp(self):
        self.selector_before = os.environ.pop(_SELECTOR, _MISSING)

    def tearDown(self):
        if self.selector_before is _MISSING:
            os.environ.pop(_SELECTOR, None)
        else:
            os.environ[_SELECTOR] = self.selector_before

    def test_default_execution_reports_and_stopped_storage_match(self):
        cases = []
        for typ in ('i8', 'u8', 'i16', 'u16', 'i32', 'u32',
                    'i64', 'u64', 'isize', 'usize'):
            lo, hi = program_module.integer_range(typ)
            cases.extend([
                (typ + '-checked', arithmetic(typ=typ), 'calculate', (hi - 1, 1), _LIMITS),
                (typ + '-overflow', arithmetic(typ=typ), 'calculate', (hi, 1), _LIMITS),
                (typ + '-wrap', arithmetic('int.add.wrap', typ), 'calculate', (hi, 1), _LIMITS),
            ])
        for op, args in (
            ('int.div.checked', (-7, 3)), ('int.rem.checked', (-7, 3)),
            ('int.div.checked', (1, 0)), ('int.rem.checked', (-(1 << 31), -1)),
            ('int.shl.checked', (1, 31)), ('int.shl.checked', (1, 32)),
            ('int.shr.checked', (-8, 2)), ('int.shr.checked', (1, -1)),
        ):
            cases.append((op + repr(args), arithmetic(op), 'calculate', args, _LIMITS))
        for size, value, limits in (
            (1, 0, _LIMITS), (17, 97, _LIMITS), (0, 1, _LIMITS),
            (100, 7, (4_000_000, 10, None, 128)),
            (4, 7, (4_000_000, 16 << 20, 1, 128)),
        ):
            cases.append(('resource-' + repr((size, value, limits)),
                          resource_program(), 'owned', (size, value), limits))
        for condition in (True, False):
            cases.append(('joined-' + str(condition), joined_loan_program(),
                          'join', (condition,), _LIMITS))
        loop = m(f('forever', [], [], [], [
            b('entry', [], [], jump('loop')), b('loop', [], [], jump('loop'))]))
        recursive = m(f('again', [('x', 'i32')], ['i32'], [], [
            b('entry', [('x', 'i32')],
              [i('call', ['x'], [('y', 'i32')], function='again')], ret('y'))]))
        cases.extend([
            ('step-limit', loop, 'forever', (), (12, 16 << 20, None, 128)),
            ('call-limit', recursive, 'again', (0,), (4_000_000, 16 << 20, None, 5)),
        ])
        for label, raw, function, arguments, limits in cases:
            with self.subTest(case=label):
                checked = verify_program(raw)
                expected = _observe(checked, function, arguments, limits)
                prepared = prepare_runtime_program(checked)
                self.assertIsNot(prepared, checked)
                self.assertEqual(_observe(prepared, function, arguments, limits), expected)
        checked = verify_program(_borrowed_program())
        prepared = prepare_runtime_program(checked)
        for value in (0, 255):
            expected = _observe_borrowed(checked, value)
            self.assertEqual(_observe_borrowed(prepared, value), expected)
            self.assertEqual(expected['whole_external_buffers'],
                             (bytes((value, 32, 33)), bytes((value, 41, 42, 43)),
                              bytes((50, value, 52, 53, 54))))

    def test_readonly_snapshot_and_fresh_entry_state(self):
        checked = verify_program(resource_program())
        ordinary_one, ordinary_two = checked.as_dict(), checked.as_dict()
        self.assertIsNot(ordinary_one, ordinary_two)
        ordinary_one['functions'][0]['blocks'][0]['ops'][0]['attrs']['unrelated'] = True
        self.assertNotIn('unrelated', ordinary_two['functions'][0]['blocks'][0]['ops'][0]['attrs'])
        prepared = prepare_runtime_program(checked)
        snapshot = prepared.as_dict()
        self.assertIs(prepared.as_dict(), snapshot)
        with self.assertRaises(TypeError):
            snapshot['functions'][0]['name'] = 'changed'
        with self.assertRaises(TypeError):
            snapshot['functions'][0]['blocks'][0]['ops'][0]['attrs']['changed'] = 1
        with self.assertRaises(TypeError):
            snapshot['functions'][0] = None
        with self.assertRaises(AttributeError):
            snapshot['functions'].append(None)
        with self.assertRaises(AttributeError):
            prepared._document = ordinary_one
        with self.assertRaises(AttributeError):
            del prepared._document
        first = _Machine(prepared, *_LIMITS)
        second = _Machine(prepared, *_LIMITS)
        self.assertIsNot(first, second)
        self.assertIsNot(first.functions, second.functions)
        self.assertIsNot(first.owners, second.owners)
        self.assertIsNot(first.chains, second.chains)
        self.assertEqual(first.invoke(first.functions['owned'], [8, 17]), [17])
        self.assertGreater(first.steps, 0)
        self.assertEqual(second.steps, 0)
        self.assertEqual(second.allocations, 0)
        self.assertEqual(second.owner_count, 0)
        self.assertEqual(second.owners, {})
        self.assertEqual(second.chains, {})
        del first.functions['owned']
        self.assertIn('owned', second.functions)
        third = _Machine(prepared, *_LIMITS)
        self.assertEqual(_machine_state(third), _machine_state(second))
        self.assertEqual(second.invoke(second.functions['owned'], [8, 17]), [17])
        self.assertEqual(third.invoke(third.functions['owned'], [8, 17]), [17])
        self.assertEqual(_machine_state(second), _machine_state(third))
        self.assertEqual(second.owner_count, 1)
        self.assertEqual(second.allocations, 1)
        self.assertEqual(second.frees, 1)
        self.assertEqual(second.max_steps, 4_000_000)
        self.assertEqual(second.max_heap_bytes, 16 << 20)
        self.assertEqual(second.max_call_depth, 128)

    def test_changed_bytes_bindings_selectors_and_custom_providers_use_original(self):
        checked = verify_program(arithmetic())
        prepared = prepare_runtime_program(checked)
        original_document = checked.as_dict()
        custom = _CustomProgram(original_document)
        self.assertIs(prepare_runtime_program(custom), custom)
        self.assertEqual(custom.calls, [])
        derived = _DerivedProgram(checked.canonical_bytes)
        self.assertIs(prepare_runtime_program(derived), derived)

        changed = verify_program(arithmetic('int.mul.checked'))
        before = checked.canonical_bytes
        try:
            object.__setattr__(checked, 'canonical_bytes', changed.canonical_bytes)
            expected = _observe(checked, 'calculate', (2, 3))
            self.assertEqual(_observe(prepared, 'calculate', (2, 3)), expected)
            self.assertEqual(expected['report']['result'], 6)
        finally:
            object.__setattr__(checked, 'canonical_bytes', before)
        self.assertEqual(_observe(prepared, 'calculate', (2, 3))['report']['result'], 5)

        before = checked.structured_bytes
        try:
            object.__setattr__(checked, 'structured_bytes', b'changed explicit input identity')
            expected = _observe(checked, 'calculate', (2, 3))
            self.assertEqual(_observe(prepared, 'calculate', (2, 3)), expected)
            self.assertEqual(prepared.input_sha256, checked.input_sha256)
        finally:
            object.__setattr__(checked, 'structured_bytes', before)

        error = MemoryError('controlled changed as_dict')
        replacement = _MethodReplacement(original_document, error)
        with _Attribute(VerifiedProgram, 'as_dict', replacement):
            self.assertIs(prepare_runtime_program(checked), checked)
            for actual in (checked, prepared):
                with self.assertRaises(MemoryError) as caught:
                    _Machine(actual, *_LIMITS)
                self.assertIs(caught.exception, error)
        self.assertEqual(replacement.calls, ['as_dict', 'as_dict'])

        # Exact VerifiedProgram is slotted: an instance as_dict override is
        # impossible there. A normal subclass does have an instance dictionary
        # and must retain its original, customized path without preparation.
        with self.assertRaises(AttributeError):
            object.__getattribute__(checked, '__dict__')
        replacement = _MethodReplacement(original_document)
        with self.assertRaises(AttributeError):
            object.__setattr__(checked, 'as_dict', replacement)
        try:
            object.__setattr__(derived, 'as_dict', replacement)
            self.assertIs(prepare_runtime_program(derived), derived)
            _Machine(derived, *_LIMITS)
            _Machine(prepare_runtime_program(derived), *_LIMITS)
            self.assertEqual(replacement.calls, ['as_dict', 'as_dict'])
        finally:
            object.__delattr__(derived, 'as_dict')


        for field, value in (('canonical_bytes', changed.canonical_bytes),
                             ('structured_bytes', b'controlled descriptor identity')):
            descriptor = _ProgramFieldReplacement(field, value)
            with self.subTest(program_field=field):
                with _Attribute(VerifiedProgram, field, descriptor):
                    self.assertIs(prepare_runtime_program(checked), checked)
                    self.assertEqual(descriptor.calls, [])
                    expected = _observe(checked, 'calculate', (2, 3))
                    original_calls = list(descriptor.calls)
                    self.assertTrue(original_calls)
                    descriptor.calls.clear()
                    self.assertEqual(_observe(prepared, 'calculate', (2, 3)), expected)
                    self.assertEqual(descriptor.calls, original_calls)

        field_error = MemoryError('controlled canonical member descriptor')
        descriptor = _ProgramFieldReplacement('canonical_bytes', None, field_error)
        with _Attribute(VerifiedProgram, 'canonical_bytes', descriptor):
            self.assertIs(prepare_runtime_program(checked), checked)
            self.assertEqual(descriptor.calls, [])
            for actual in (checked, prepared):
                with self.assertRaises(MemoryError) as caught:
                    _Machine(actual, *_LIMITS)
                self.assertIs(caught.exception, field_error)
        self.assertEqual(descriptor.calls, ['canonical_bytes', 'canonical_bytes'])

        for field in ('canonical_bytes', 'structured_bytes'):
            before_slot = object.__getattribute__(checked, field)
            try:
                object.__delattr__(checked, field)
                self.assertIs(prepare_runtime_program(checked), checked)
                if field == 'canonical_bytes':
                    errors = []
                    for actual in (checked, prepared):
                        with self.assertRaises(AttributeError) as caught:
                            actual.as_dict()
                        errors.append((type(caught.exception), caught.exception.args,
                                       caught.exception.name,
                                       caught.exception.obj is checked))
                    self.assertEqual(errors[0], errors[1])
                    self.assertTrue(errors[0][-1])
                else:
                    self.assertEqual(prepared.as_dict(), checked.as_dict())
            finally:
                object.__setattr__(checked, field, before_slot)

        for owner, name in ((program_module, 'decode_internal_canonical'),
                            (decoder_module, 'decode_internal_canonical'),
                            (decoder_module.json, 'loads')):
            replacement = _DecodeReplacement(original_document)
            with self.subTest(binding=name, module=getattr(owner, '__name__', None)):
                with _Attribute(owner, name, replacement):
                    self.assertIs(prepare_runtime_program(checked), checked)
                    expected = _observe(checked, 'calculate', (2, 3))
                    self.assertEqual(_observe(prepared, 'calculate', (2, 3)), expected)
                    if owner is not decoder_module:
                        self.assertEqual(len(replacement.calls), 2)
                        self.assertEqual(replacement.calls[0], replacement.calls[1])
                    else:
                        # VerifiedProgram has its own imported decoder binding.
                        self.assertEqual(replacement.calls, [])

        default_decoder = decoder_module.json._default_decoder
        replacement_decoder = _SelectedDecoder(original_document)
        with _Attribute(decoder_module.json, '_default_decoder', replacement_decoder):
            self.assertIs(prepare_runtime_program(checked), checked)
            expected = _observe(checked, 'calculate', (2, 3))
            self.assertEqual(_observe(prepared, 'calculate', (2, 3)), expected)
        self.assertEqual(len(replacement_decoder.calls), 2)
        self.assertEqual(replacement_decoder.calls[0], replacement_decoder.calls[1])

        for method in ('decode', 'raw_decode'):
            replacement_value = (original_document if method == 'decode'
                                 else (original_document, len(checked.canonical_bytes.decode('utf-8'))))
            for target in ('instance', 'class'):
                replacement = _DecodeReplacement(replacement_value)
                scope = (_DictionaryEntry(object.__getattribute__(default_decoder, '__dict__'),
                                          method, replacement) if target == 'instance'
                         else _Attribute(type(default_decoder), method, replacement))
                with self.subTest(default_decoder_method=method, target=target):
                    with scope:
                        self.assertIs(prepare_runtime_program(checked), checked)
                        expected = _observe(checked, 'calculate', (2, 3))
                        self.assertEqual(_observe(prepared, 'calculate', (2, 3)), expected)
                    self.assertEqual(len(replacement.calls), 2)
                    self.assertEqual(replacement.calls[0], replacement.calls[1])

        scanner = _ScanReplacement(original_document)
        with _DictionaryEntry(object.__getattribute__(default_decoder, '__dict__'), 'scan_once', scanner):
            self.assertIs(prepare_runtime_program(checked), checked)
            expected = _observe(checked, 'calculate', (2, 3))
            self.assertEqual(_observe(prepared, 'calculate', (2, 3)), expected)
        self.assertEqual(len(scanner.calls), 2)
        self.assertEqual(scanner.calls[0], scanner.calls[1])

        encoding = _EncodingReplacement()
        with _Attribute(decoder_module.json, 'detect_encoding', encoding):
            self.assertIs(prepare_runtime_program(checked), checked)
            expected = _observe(checked, 'calculate', (2, 3))
            self.assertEqual(_observe(prepared, 'calculate', (2, 3)), expected)
        self.assertEqual(encoding.calls, [checked.canonical_bytes, checked.canonical_bytes])

        replacement = _DecodeReplacement(original_document)
        with _Attribute(program_module, 'decode_internal_canonical', replacement):
            with _Attribute(program_module, 'MAX_NODES', program_module.MAX_NODES - 1):
                expected = _observe(checked, 'calculate', (2, 3))
                self.assertEqual(_observe(prepared, 'calculate', (2, 3)), expected)
                self.assertEqual(replacement.calls[0][1]['max_nodes'], program_module.MAX_NODES)
                self.assertEqual(replacement.calls[0], replacement.calls[1])

        with _DictionaryEntry(os.environ, _SELECTOR, ''):
            self.assertIs(prepare_runtime_program(checked), checked)
            errors = []
            for actual in (checked, prepared):
                with self.assertRaises(ValueError) as caught:
                    _Machine(actual, *_LIMITS)
                errors.append((type(caught.exception), caught.exception.args))
            self.assertEqual(errors[0], errors[1])
            self.assertEqual(errors[0][1], ('JSON decoder selector must not be empty',))

        fake_module = ModuleType('hepta.hia_json_decode_native')
        selected = _SelectedDecoder(original_document)
        fake_module.installed_decoder = selected
        with _DictionaryEntry(sys.modules, 'hepta.hia_json_decode_native', fake_module):
            with _DictionaryEntry(os.environ, _SELECTOR, 'explicit-controlled-decoder'):
                self.assertIs(prepare_runtime_program(checked), checked)
                expected = _observe(checked, 'calculate', (2, 3))
                self.assertEqual(_observe(prepared, 'calculate', (2, 3)), expected)
        self.assertEqual([call[0] for call in selected.calls],
                         ['installed_decoder', 'decode', 'installed_decoder', 'decode'])
        self.assertEqual(selected.calls[:2], selected.calls[2:])


if __name__ == '__main__':
    unittest.main()
