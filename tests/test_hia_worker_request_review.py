"""Independent ordinary-wire, request-policy and native ABI adversarial checks.

The references below use stdlib JSON and SHA-256 directly, not the generator or
the worker's retained helpers. Native build custody is shared with the worker
integration suite; a development manifest remains explicitly unqualified.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import ctypes
from hashlib import sha256
import json
import math
import random
import struct
import unittest
from unittest.mock import patch

from hepta.hia_worker_request_native import (
    MAX_BYTES, PRIVATE_BYTES, NativeRequestRejected, buffer_sizes,
)
from tests import test_hia_worker_request_native as integration


CATALOG = '2' * 64


def ordinary_wire(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def envelope(arguments=None, *, tool='hia_describe', catalog=CATALOG):
    # Deliberately preserve the ordinary unsorted request-member order.
    value = {'schema': 'hia-agent-worker-request-v1', 'tool': tool,
             'arguments': {'z': 0, 'a': 1.25} if arguments is None else arguments,
             'profile_sha256': '1' * 64, 'catalog_sha256': catalog}
    value['request_sha256'] = sha256(ordinary_wire(value)).hexdigest()
    return value


def source_wire(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'),
                      allow_nan=False).encode('utf-8')


def value_identity(value):
    """Keep float bits, numeric types and source insertion order observable."""
    if type(value) is float:
        return ('float', struct.pack('<d', value).hex())
    if type(value) is list:
        return ('list', tuple(value_identity(item) for item in value))
    if type(value) is dict:
        return ('dict', tuple((key, value_identity(item)) for key, item in value.items()))
    return (type(value).__name__, value)


class WorkerRequestAdversarialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        integration.WorkerRequestNativeTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        integration.WorkerRequestNativeTests.tearDownClass.__func__(cls)

    def rejected(self, value, code, message=None):
        raw = source_wire(value)
        with self.assertRaises(NativeRequestRejected) as caught:
            self.native.admit(raw, CATALOG)
        error = caught.exception
        self.assertEqual(error.code, code)
        if message is not None:
            self.assertEqual(str(error), message)
        self.assertEqual(value_identity(error.request), value_identity(value))
        return error

    def test_source_order_arena_is_restored_after_success_and_all_semantic_refusals(self):
        arguments = {'z': [{'z': -0.0, 'a': 17}, {'x': 1.0}],
                     'a': {'request_sha256': 'nested identity stays', 'a': []}}
        value = envelope(arguments)
        self.assertEqual(value_identity(self.native.admit(source_wire(value), CATALOG)),
                         value_identity(value))
        changed = {**value, 'extra': True}
        self.rejected(changed, 'E_HIA_FIELDS', 'worker request has missing or unknown fields')
        changed = {**value, 'schema': 'unknown', 'request_sha256': 'not a digest'}
        self.rejected(changed, 'E_HIA_WORKER_SCHEMA', 'unknown worker envelope')
        self.rejected({**value, 'profile_sha256': 'A' * 64}, 'E_HIA_WORKER_IDENTITY',
                      'invalid worker digest field')
        self.rejected({**value, 'request_sha256': '0' * 64}, 'E_HIA_WORKER_IDENTITY',
                      'worker request digest mismatch')
        self.rejected(envelope(arguments, catalog='3' * 64, tool=7),
                      'E_HIA_CATALOG_STALE', 'worker request catalog differs from installed bytes')
        self.rejected(envelope(arguments, tool=7), 'E_HIA_WORKER_TOOL',
                      'invalid worker tool name')

    def test_only_root_digest_is_omitted_and_noncanonical_raw_has_same_identity(self):
        arguments = {'request_sha256': 'nested', 'z': [1e15, -0.0, 0],
                     'a': {'catalog_sha256': 'argument value'}}
        value = envelope(arguments)
        raw = json.dumps(value, indent=2, ensure_ascii=True).encode()
        raw = raw.replace(b'1000000000000000.0', b'1e15')
        raw = raw.replace(b'"request_sha256"', b'"request_\\u0073ha256"')
        actual = self.native.admit(raw, CATALOG)
        self.assertEqual(value_identity(actual), value_identity(value))
        altered = {**value, 'arguments': {**arguments, 'request_sha256': 'different'}}
        self.rejected(altered, 'E_HIA_WORKER_IDENTITY', 'worker request digest mismatch')
        # Digest mismatch wins over stale catalog and wrong tool type.
        altered = envelope(arguments, catalog='3' * 64, tool=[])
        altered['request_sha256'] = '0' * 64
        self.rejected(altered, 'E_HIA_WORKER_IDENTITY', 'worker request digest mismatch')

    def test_parsed_rejections_preserve_original_correlation_presence_rule(self):
        original = envelope({'z': 1, 'a': 0})
        cases = []
        for missing in ('schema', 'arguments', 'request_sha256', 'profile_sha256', 'catalog_sha256', 'tool'):
            value = {key: item for key, item in original.items() if key != missing}
            correlated = missing in ('schema', 'arguments')
            cases.append((value, 0 if correlated else 2,
                          'E_HIA_FIELDS' if correlated else None))
        cases.extend((([], 2, None),
                      ({**original, 'request_sha256': []}, 0, 'E_HIA_WORKER_IDENTITY'),
                      ({**original, 'profile_sha256': {}}, 0, 'E_HIA_WORKER_IDENTITY')))
        for index, (value, expected_code, error_code) in enumerate(cases):
            state = self.folder / ('adversarial-correlation-' + str(index))
            with self.subTest(value=value):
                code, report, _ = integration.WorkerRequestNativeTests.call_worker(
                    self, source_wire(value), state)
                self.assertEqual(code, expected_code)
                if error_code is None:
                    self.assertIsNone(report)
                else:
                    self.assertEqual(report['response']['error']['code'], error_code)
                    for key in ('tool', 'request_sha256', 'profile_sha256', 'catalog_sha256'):
                        self.assertEqual(report[key], value[key])
                self.assertFalse(state.exists())

    def test_tool_limit_counts_unicode_scalars_and_arguments_policy_is_delegated(self):
        for tool in ('', 'x' * 128, '\U0001f600' * 128, 'e\u0301' * 64, '\x00'):
            for arguments in (None, False, 7, [], {'z': 0, 'a': 1}):
                value = envelope(arguments, tool=tool)
                if arguments is None:
                    value['arguments'] = None
                    value['request_sha256'] = sha256(ordinary_wire(
                        {key: item for key, item in value.items() if key != 'request_sha256'})).hexdigest()
                with self.subTest(tool=repr(tool[:8]), arguments=arguments):
                    actual = self.native.admit(source_wire(value), CATALOG)
                    self.assertEqual(value_identity(actual), value_identity(value))
        for tool in ('x' * 129, '\U0001f600' * 129, 'e\u0301' * 65, 0, False, [], {}):
            self.rejected(envelope(tool=tool), 'E_HIA_WORKER_TOOL', 'invalid worker tool name')
        for trusted in (None, '2' * 63, 'A' * 64, 0, b'2' * 64):
            with self.subTest(trusted=trusted), self.assertRaises(ValueError):
                self.native.admit(source_wire(envelope()), trusted)

    def test_finite_binary64_bits_shortest_rendering_and_decimal_rounding(self):
        values = [0.0, -0.0, 5e-324, -5e-324, 2.225073858507201e-308,
                  2.2250738585072014e-308, 1.7976931348623157e308,
                  1e-5, 1e-4, 1e15, 1e16, 9007199254740992.0]
        rng = random.Random(74117)
        while len(values) < 256:
            value = struct.unpack('<d', rng.getrandbits(64).to_bytes(8, 'little'))[0]
            if math.isfinite(value):
                values.append(value)
        raw = ordinary_wire(values)
        self.assertEqual(self.native.canonicalize(raw), raw)
        value = envelope({'z': values, 'a': -0.0})
        self.assertEqual(value_identity(self.native.admit(source_wire(value), CATALOG)),
                         value_identity(value))
        lexemes = (b'-0', b'-0.000', b'0E99999', b'-0E99999', b'1e-99999', b'-1e-99999',
                   b'2.4703282292062327e-324', b'2.4703282292062328e-324',
                   b'1.7976931348623158e308', b'9007199254740993.0',
                   b'1.' + b'0' * 799 + b'1', b'0.' + b'0' * 2000 + b'1')
        for raw in lexemes:
            with self.subTest(raw=raw[:48], size=len(raw)):
                self.assertEqual(self.native.canonicalize(raw), ordinary_wire(json.loads(raw)))

    def test_plain_json_unicode_order_escapes_and_types_match_independent_wire(self):
        values = (None, True, False, [], {}, [0, -0.0, 1.0, 2**128],
                  {'\U0010ffff': 'last', '\ue000': 'bmp', '\U00010000': 'supplementary',
                   'a\x00': '\b\t\n\f\r\x00\x1f"\\/', 'a': '\u2028\u2029',
                   '\u00e9': 0, 'e\u0301': 1}, {'z': {'z': 1, 'a': 2}, 'a': [False, None]})
        for value in values:
            raw = json.dumps(value, ensure_ascii=True, indent=1).encode()
            with self.subTest(value=value):
                self.assertEqual(self.native.canonicalize(raw), ordinary_wire(value))

    def test_syntax_unicode_duplicate_nonfinite_and_depth_never_return_correlated_request(self):
        malformed = (b'', b'{', b'[] []', b'[1,]', b'{"a":1,"\\u0061":2}',
                     b'NaN', b'Infinity', b'-Infinity', b'1e400', b'-1e400',
                     b'1.7976931348623159e308', b'"\\ud800"', b'"\xc0\x80"',
                     b'"\xed\xa0\x80"', b'"\xf4\x90\x80\x80"',
                     b'[' * 129 + b'0' + b']' * 129)
        for raw in malformed:
            with self.subTest(raw=raw[:64]):
                try:
                    self.native.admit(raw, CATALOG)
                except ValueError as error:
                    self.assertNotIsInstance(error, NativeRequestRejected)
                    self.assertFalse(hasattr(error, 'request'))
                else:
                    self.fail('malformed input was admitted')
        raw = b'[' * 128 + b'0' + b']' * 128
        self.assertEqual(self.native.canonicalize(raw), raw)
        # Parsing every numeric value precedes the otherwise-wrong schema.
        raw = source_wire({**envelope(), 'schema': 'wrong'})
        raw = raw.replace(b'1.25', b'1e400')
        with self.assertRaises(ValueError) as caught:
            self.native.admit(raw, CATALOG)
        self.assertNotIsInstance(caught.exception, NativeRequestRejected)

    def test_configured_integer_digit_limit_precedes_envelope_fields(self):
        with patch('hepta.hia_worker_request_native.sys.get_int_max_str_digits', return_value=640):
            for raw in (b'1' * 640, b'-' + b'1' * 640):
                self.assertEqual(self.native.canonicalize(raw), raw)
            for raw in (b'1' * 641, b'-' + b'1' * 641, b'{"x":' + b'1' * 641 + b'}'):
                with self.subTest(size=len(raw)), self.assertRaises(ValueError) as caught:
                    self.native.admit(raw, CATALOG)
                self.assertNotIsInstance(caught.exception, NativeRequestRejected)
        # Disabled limit is an administrator numeric profile, not a request field.
        with patch('hepta.hia_worker_request_native.sys.get_int_max_str_digits', return_value=0):
            raw = b'1' * 5000
            self.assertEqual(self.native.canonicalize(raw), raw)

    def test_native_buffer_bounds_and_readonly_source_canaries(self):
        guard = 64
        sentinel = b'\xa7' * guard

        def guarded(size):
            buffer = ctypes.create_string_buffer(sentinel + b'\x00' * size + sentinel,
                                                 size + 2 * guard)
            return buffer, ctypes.addressof(buffer) + guard

        cases = [(b'{"z":1e15,"a":[-0.0,17]}', 0, 8192, 0, None),
                 (source_wire(envelope()), 1, 8192, 0, None),
                 (b'{}', 0, 127, 0, 0xfffffffd),
                 (b'{}', 0, 128, 0, 0xfffffffd),
                 (b'[' + b'0,' * 80 + b'0]', 0, 8192, -1, 0xfffffffd),
                 (b'{}', 2, 8192, 0, 0xfffffffd),
                 (b'{"x":1,"\\u0078":2}', 0, 8192, 0, 0xfffffffc)]
        for raw, mode, output_size, scratch_delta, expected in cases:
            _, needed = buffer_sizes(len(raw))
            scratch_size = needed + scratch_delta
            source, source_pointer = guarded(len(raw))
            output, output_pointer = guarded(output_size)
            scratch, scratch_pointer = guarded(scratch_size)
            ctypes.memmove(source_pointer, raw, len(raw))
            struct.pack_into('<2Q', scratch, guard, mode, 4300)
            if mode == 1:
                ctypes.memmove(scratch_pointer + scratch_size - PRIVATE_BYTES + 64,
                               CATALOG.encode(), 64)
            with self.subTest(raw=raw[:40], mode=mode, output=output_size, delta=scratch_delta):
                code = self.native._entry(source_pointer, len(raw), output_pointer, output_size,
                                          scratch_pointer, scratch_size)
                if expected is not None:
                    self.assertEqual(code, expected)
                else:
                    value = json.loads(raw)
                    if mode:
                        value = {key: item for key, item in value.items() if key != 'request_sha256'}
                    expected_bytes = ordinary_wire(value)
                    self.assertEqual((code, ctypes.string_at(output_pointer, code)),
                                     (len(expected_bytes), expected_bytes))
                self.assertEqual(source.raw, sentinel + raw + sentinel)
                for buffer in (output, scratch):
                    self.assertEqual(buffer.raw[:guard], sentinel)
                    self.assertEqual(buffer.raw[-guard:], sentinel)

    def test_request_admission_uses_digest_body_budget_not_complete_envelope_budget(self):
        def expanded_request(padding):
            value = envelope({'pad': 'x' * padding, 'f': 1e15})
            return value, source_wire(value).replace(b'1000000000000000.0', b'1e15')

        _, empty = expanded_request(0)
        value, raw = expanded_request(MAX_BYTES - len(empty))
        self.assertEqual(len(raw), MAX_BYTES)
        self.assertGreater(len(ordinary_wire(value)), MAX_BYTES)
        digest_input = {key: item for key, item in value.items() if key != 'request_sha256'}
        self.assertLessEqual(len(ordinary_wire(digest_input)), MAX_BYTES)
        self.assertEqual(self.native.admit(raw, CATALOG), value)
        with self.assertRaises(ValueError):
            self.native.canonicalize(raw)
        with self.assertRaises(ValueError):
            self.native.admit(raw + b' ', CATALOG)

    def test_direct_admission_has_no_foreign_payload_parser_encoder_or_digest_fallback(self):
        value = envelope({'z': [1.25, -0.0], 'a': {'request_sha256': 'nested'}})
        raw = source_wire(value)
        expected = value_identity(value)
        with patch('json.loads', side_effect=AssertionError('foreign payload parser')), \
                patch('json.dumps', side_effect=AssertionError('foreign payload encoder')), \
                patch('hashlib.sha256', side_effect=AssertionError('foreign payload digest')):
            actual = self.native.admit(raw, CATALOG)
        self.assertEqual(value_identity(actual), expected)

    def test_concurrent_calls_keep_trusted_catalog_and_source_order_private(self):
        values = [envelope({'z': index, 'a': [index + 0.25, -0.0]},
                           catalog=str(index % 10) * 64) for index in range(24)]
        with ThreadPoolExecutor(max_workers=6) as pool:
            observed = list(pool.map(lambda value: self.native.admit(
                source_wire(value), value['catalog_sha256']), values))
        self.assertEqual([value_identity(value) for value in observed],
                         [value_identity(value) for value in values])


if __name__ == '__main__':
    unittest.main()
