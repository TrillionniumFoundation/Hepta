"""Independent controls for the optional HIA immutable-key cache protocol.

The cache is an execution optimization after ordinary key admission. Custom
observers retain the old requests, and capacity misses never reduce the domain.
"""
from __future__ import annotations

import ctypes
import json
import struct
import sys
import unittest
from unittest.mock import patch

from hepta import hia_json_wire_native as native
from hepta import hia_program_tools as program_tools
from tests import test_hia_json_wire_native as base_tests

outcome = base_tests.outcome


def run_observed(image, value, maximum=4096, *, cache, ensure_ascii=False,
                 sort_keys=True, observer=None, renderer=None):
    observer = native.ForeignGraphObserver() if observer is None else observer
    session = native.WireSession(image, observer, observer.register(value), maximum,
                                 ensure_ascii=ensure_ascii, sort_keys=sort_keys,
                                 float_renderer=renderer, _builtin_keys=cache)
    trace = []
    original = session.step

    def step(packet=None):
        result = original(packet)
        if result == 1:
            opcode, sequence = struct.unpack_from('<2Q', session.workspace, 8)
            request = struct.unpack_from('<4Q', session.workspace, 200)
            trace.append((opcode, sequence, *request))
        return result

    session.step = step
    result = outcome(session.run)
    stats = struct.unpack_from('<3Q', session.workspace, 656)
    return result, trace, stats, session


class WireCacheNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Preserve the normal source-admitted cold/development fixture split.
        base_tests.WireNativeTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        base_tests.WireNativeTests.tearDownClass.__func__(cls)

    def compare(self, value, maximum=4096, **options):
        old = outcome(lambda: program_tools._reference_bounded_json_wire(value, maximum, **options))
        uncached = run_observed(self.image, value, maximum, cache=False, **options)
        cached = run_observed(self.image, value, maximum, cache=True, **options)
        self.assertEqual(uncached[0], old)
        self.assertEqual(cached[0], old)
        self.assertFalse(uncached[3].key_cache)
        self.assertTrue(cached[3].key_cache)
        return uncached, cached

    def test_repeated_immutable_keys_reduce_only_codepoint_observations(self):
        keys = ('gamma', 'alpha', 'beta', '', '雪', '🧪', 'quote"slash\\')
        shared = {key: index for index, key in enumerate(keys)}
        value = [shared, dict(shared), shared]
        for ascii_flag in (False, True):
            for sort_flag in (False, True):
                with self.subTest(ascii=ascii_flag, sort=sort_flag):
                    old, new = self.compare(value, ensure_ascii=ascii_flag, sort_keys=sort_flag)
                    self.assertGreater(new[2][0], 0)
                    self.assertEqual(new[2][2], len(keys))
                    # Sequence numbers change because redundant POINTS calls
                    # disappear, but every other foreign request is retained.
                    nonpoints = lambda trace: [(r[0], *r[2:]) for r in trace if r[0] != native.POINTS]
                    self.assertEqual(nonpoints(old[1]), nonpoints(new[1]))
                    self.assertLess(sum(r[0] == native.POINTS for r in new[1]),
                                    sum(r[0] == native.POINTS for r in old[1]))

    def test_capacity_and_handle_collisions_fall_back_without_refusal(self):
        keys = ['key-' + str(index).zfill(4) for index in range(1025)]
        value = {key: 0 for key in keys}
        observer = native.ForeignGraphObserver()
        for index, key in enumerate(keys, 1):
            self.assertEqual(observer.register(key), index)
        result, _, stats, session = run_observed(
            self.image, value, 230000, cache=True, observer=observer)
        self.assertEqual(result, outcome(lambda: program_tools._reference_bounded_json_wire(
            value, 230000, ensure_ascii=False, sort_keys=True)))
        self.assertTrue(session.key_cache)
        self.assertEqual(stats[2], 1024)
        self.assertGreater(stats[0], 0)
        self.assertGreater(stats[1], 1024)
        base, = struct.unpack_from('<Q', session.workspace, 648)
        # Handles 1 and 1025 share a slot. The admitted first key survives;
        # the second uses the original HIA normalization on every miss.
        self.assertEqual(struct.unpack_from('<Q', session.workspace, base + 160)[0], 1)
        self.assertEqual(observer.value(1), keys[0])
        self.assertIs(observer.value(1025), keys[-1])

    def test_budget_unicode_and_error_order_match_reference(self):
        cycle = []
        cycle.append(cycle)
        examples = [
            [{'same': 1}, {'same': 2, 'later': '\ud800'}],
            [{'same': 'x' * 256}, {'later': '\ud800'}],
            [{'same': 1}, cycle],
            {'same': float('nan')},
            {'雪' * 32: 1, 'a' * 33: 2},
            {'🧪' * 32: 1},
            {'a': {1: 0, '1': 1}},
        ]
        for value in examples:
            for maximum in (0, 1, 2, 16, 128, 4096):
                with self.subTest(value_type=type(value).__name__, maximum=maximum):
                    self.compare(value, maximum, ensure_ascii=False, sort_keys=True)
        for extra in (0, 1):
            value = {'cache': 'x' * (230000 - 12 + extra)}
            old, new = self.compare(value, 230000, ensure_ascii=False, sort_keys=True)
            if extra == 0:
                self.assertEqual(len(new[0][1]), 230000)
            else:
                self.assertEqual(new[0], ('HIAEditRejected', 'E_HIA_EDIT: JSON encoding exceeds byte budget'))
        self.compare({'cache': '\0' * 65536}, 230000, ensure_ascii=False, sort_keys=True)

    def test_subtypes_custom_observers_and_replaced_instance_methods_stay_uncached(self):
        class Text(str):
            def __len__(self):
                raise AssertionError('str subtype length hook entered')
            def __str__(self):
                raise AssertionError('str subtype string hook entered')
        for value in ({Text('key'): 1}, {'key': Text('value')}):
            self.compare(value, ensure_ascii=False, sort_keys=True)

        class Custom(native.ForeignGraphObserver):
            def points(self, handle, start, count):
                return super().points(handle, start, count)
        graph = [{'b': 1, 'a': 2}] * 3
        for factory in (Custom, native.ForeignGraphObserver):
            observations = []
            for cache in (False, True):
                observer = factory()
                if factory is native.ForeignGraphObserver:
                    original = observer.points
                    observer.points = lambda h, s, c: original(h, s, c)
                result = run_observed(self.image, graph, cache=cache, observer=observer)
                self.assertFalse(result[3].key_cache)
                observations.append((result[0], result[1], bytes(result[3].workspace)))
            self.assertEqual(observations[0], observations[1])

        original = native.ForeignGraphObserver.points
        with patch.object(native.ForeignGraphObserver, 'points', lambda self, *args: original(self, *args)):
            new = run_observed(self.image, graph, cache=True)
            self.assertFalse(new[3].key_cache)
        with patch.object(sys, 'get_int_max_str_digits', lambda: 0):
            new = run_observed(self.image, graph, cache=True)
            self.assertFalse(new[3].key_cache)

    def test_explicit_renderer_keeps_original_observations_and_callbacks(self):
        value = [{'b': 1.5, 'a': 2}] * 3
        observations = []
        for cache in (False, True):
            calls = []
            def render(number):
                calls.append(number)
                return '1.5'
            result = run_observed(self.image, value, cache=cache, renderer=render)
            self.assertFalse(result[3].key_cache)
            observations.append((result[0], result[1], calls, bytes(result[3].workspace)))
        self.assertEqual(observations[0], observations[1])
        self.assertEqual(observations[0][2], [1.5] * 3)

    def test_capability_packet_and_memory_boundaries_reject_before_foreign_calls(self):
        def session(maximum=128):
            observer = native.ForeignGraphObserver()
            return native.WireSession(self.image, observer, observer.register({'b': 1, 'a': 2}),
                                      maximum, ensure_ascii=False, sort_keys=True, _builtin_keys=True)
        for mutation in ('cap0', 'cap2', 'short', 'long', 'old_magic', 'renderer', 'workspace'):
            value = session()
            self.assertTrue(value.key_cache)
            self.assertEqual(len(value.packet), 112)
            packet = bytearray(value.packet)
            if mutation == 'cap0': struct.pack_into('<Q', packet, 104, 0)
            if mutation == 'cap2': struct.pack_into('<Q', packet, 104, 2)
            if mutation == 'short': packet.pop()
            if mutation == 'long': packet.append(0)
            if mutation == 'old_magic': struct.pack_into('<Q', packet, 0, native.MAGIC)
            if mutation == 'renderer': struct.pack_into('<Q', packet, 96, 1)
            if mutation == 'workspace': value.workspace = ctypes.create_string_buffer(len(value.workspace) - 1)
            with self.subTest(mutation=mutation):
                self.assertEqual(value.step(bytes(packet)), 199)
        value = session()
        self.assertEqual(value.step(), 1)
        packet = bytearray(value.observe())
        struct.pack_into('<Q', packet, 0, native.MAGIC)
        self.assertEqual(value.step(bytes(packet)), 199)

        # A zero initial magic never authorizes a stale optional cache pointer
        # on the legacy protocol. Full new sessions still require zeroed state.
        observer = native.ForeignGraphObserver()
        legacy = native.WireSession(self.image, observer, observer.register({'a': 1}),
                                    128, ensure_ascii=False, sort_keys=True)
        struct.pack_into('<Q', legacy.workspace, 648, (1 << 64) - 1)
        self.assertEqual(legacy.run(), b'{"a":1}')
        self.assertEqual(struct.unpack_from('<Q', legacy.workspace, 648)[0], 0)

        for maximum in (0, 1, 2, 16, 128):
            value = session(maximum)
            output = ctypes.create_string_buffer(maximum + 32)
            workspace = ctypes.create_string_buffer(len(value.workspace) + 32)
            ctypes.memset(output, 0xA5, len(output))
            ctypes.memset(workspace, 0xA5, len(workspace))
            size = len(value.workspace)
            value.output = ctypes.cast(ctypes.byref(output, 16), ctypes.POINTER(ctypes.c_char))
            value.workspace = (ctypes.c_char * size).from_buffer(workspace, 16)
            ctypes.memset(value.workspace, 0, size)
            outcome(value.run)
            self.assertEqual(output.raw[:16] + output.raw[-16:], b'\xa5' * 32)
            self.assertEqual(workspace.raw[:16] + workspace.raw[-16:], b'\xa5' * 32)

    def test_ordinary_entry_selects_cache_without_retained_encoder(self):
        seen = []
        original = native.WireSession.run
        def run(session):
            seen.append((session.key_cache, session._protocol_magic))
            return original(session)
        value = [{'b': 1, 'a': 2}] * 4
        expected = program_tools._reference_bounded_json_wire(value, 4096, ensure_ascii=False)
        with patch.object(native.WireSession, 'run', run), \
                patch.object(program_tools, '_reference_bounded_json_wire', side_effect=AssertionError('retained owner entered')), \
                patch.object(json.JSONEncoder, 'iterencode', side_effect=AssertionError('host encoder entered')):
            self.assertEqual(self.image.encode_ordinary(value, 4096, ensure_ascii=False), expected)
        self.assertEqual(seen, [(True, native.CACHED_MAGIC)])

