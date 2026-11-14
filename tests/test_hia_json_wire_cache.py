"""Independent controls for the optional HIA immutable-key cache protocol.

The cache is an execution optimization after ordinary key admission. Custom
observers retain the old requests, and capacity misses never reduce the domain.
"""
from __future__ import annotations

import ctypes
import json
import os
import struct
import sys
import unittest
from unittest.mock import patch

from hepta import hia_json_wire_native as native
from hepta import hia_program_tools as program_tools
from tests import test_hia_json_wire_native as base_tests

outcome = base_tests.outcome
FIXTURE_EVIDENCE = 'HEPTA_HIA_JSON_WIRE_CACHE_FIXTURE_EVIDENCE'


def run_observed(image, value, maximum=4096, *, cache, ensure_ascii=False,
                 sort_keys=True, observer=None, renderer=None, summaries=False, paired=False):
    observer = native.ForeignGraphObserver() if observer is None else observer
    session = native.WireSession(image, observer, observer.register(value), maximum,
                                 ensure_ascii=ensure_ascii, sort_keys=sort_keys,
                                 float_renderer=renderer, _builtin_keys=cache,
                                 _immutable_summaries=summaries, _paired_children=paired)
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
        evidence = os.environ.get(FIXTURE_EVIDENCE, '')
        with patch.dict(os.environ, {base_tests.FIXTURE_EVIDENCE: evidence}):
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
        with self.assertRaisesRegex(RuntimeError, 'no unconsumed observation'):
            value.observe()
        struct.pack_into('<Q', packet, 0, native.MAGIC)
        self.assertEqual(value.step(bytes(packet)), 199)
        with self.assertRaisesRegex(RuntimeError, 'terminal'):
            value.observe()

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
        self.assertEqual(seen, [(True, native.PAIRED_MAGIC)])



    def compare_summaries(self, value, maximum=4096, **options):
        expected = outcome(lambda: program_tools._reference_bounded_json_wire(value, maximum, **options))
        old = run_observed(self.image, value, maximum, cache=True, summaries=False, **options)
        new = run_observed(self.image, value, maximum, cache=True, summaries=True, **options)
        self.assertEqual(old[0], expected)
        self.assertEqual(new[0], expected)
        self.assertFalse(old[3].summary_cache)
        self.assertTrue(new[3].summary_cache)
        # Callback sequence numbers change when redundant summaries disappear.
        # Every non-summary foreign observation must keep its exact order/args.
        project = lambda trace: [(r[0], *r[2:]) for r in trace if r[0] != native.SUMMARY]
        self.assertEqual(project(old[1]), project(new[1]))
        return old, new

    def test_summary_cache_removes_only_observed_immutable_facts(self):
        shared = {'gamma': 17, 'alpha': 'value', '雪': None, 'bool': True}
        value = [shared, dict(shared), shared]
        for ascii_flag in (False, True):
            for sort_flag in (False, True):
                old, new = self.compare_summaries(
                    value, ensure_ascii=ascii_flag, sort_keys=sort_flag)
                old_summaries = [r for r in old[1] if r[0] == native.SUMMARY]
                new_summaries = [r for r in new[1] if r[0] == native.SUMMARY]
                saved, = struct.unpack_from('<Q', new[3].workspace, 712)
                self.assertEqual(saved, len(old_summaries) - len(new_summaries))
                self.assertGreater(saved, 0)
                self.assertEqual(struct.unpack_from('<3Q', old[3].workspace, 712), (0, 0, 0))
                self.assertEqual(new[3]._protocol_magic, native.SUMMARY_MAGIC)
                # Container summaries own fresh cursors and may never disappear.
                containers = lambda run: [
                    (r[0], *r[2:]) for r in run[1]
                    if r[0] == native.SUMMARY and
                    type(run[3].observer.value(r[2])) in (list, tuple, dict)]
                self.assertEqual(containers(old), containers(new))

    def test_scalar_summary_cache_keeps_container_and_digit_limit_observations(self):
        scalars = [None, True, False, 123456789, -123456789, 1.25, -0.0, 'value', '🧪']
        value = [{'repeat': scalars * 2}] * 3
        old, new = self.compare_summaries(value, 20000, ensure_ascii=False, sort_keys=True)
        self.assertGreater(sum(r[0] == native.DIGIT_LIMIT for r in old[1]), 0)
        self.assertEqual(
            [(r[0], *r[2:]) for r in old[1] if r[0] == native.DIGIT_LIMIT],
            [(r[0], *r[2:]) for r in new[1] if r[0] == native.DIGIT_LIMIT])
        stores, hits = struct.unpack_from('<2Q', new[3].workspace, 720)
        self.assertGreater(stores, 0)
        self.assertGreater(hits, 0)
        for slot in range(256):
            record = struct.unpack_from('<5Q', new[3].workspace, 16480 + slot * 40)
            if record[0] == 0:
                self.assertEqual(record, (0, 0, 0, 0, 0))
                continue
            self.assertEqual(slot, record[0] & 255)
            self.assertIn(type(new[3].observer.value(record[0])), (type(None), bool, int, float, str))
            self.assertEqual(record[1:], new[3].observer.summary(record[0]))

    def test_scalar_summary_cache_collisions_keep_original_domain(self):
        values = [1000000 + i for i in range(1025)]
        graph = [values, values]
        runs = []
        for summaries in (False, True):
            observer = native.ForeignGraphObserver()
            for handle, value in enumerate(values, 1):
                self.assertEqual(observer.register(value), handle)
            runs.append(run_observed(
                self.image, graph, 60000, cache=True, summaries=summaries,
                observer=observer, ensure_ascii=False, sort_keys=True))
        expected = outcome(lambda: program_tools._reference_bounded_json_wire(
            graph, 60000, ensure_ascii=False, sort_keys=True))
        self.assertEqual(runs[0][0], expected)
        self.assertEqual(runs[1][0], expected)
        first = {}
        for opcode, sequence, handle, index, count, part in runs[1][1]:
            if opcode == native.SUMMARY and type(runs[1][3].observer.value(handle)) is int:
                first.setdefault(handle & 255, handle)
        self.assertEqual(len(first), 256)
        self.assertEqual(struct.unpack_from('<Q', runs[1][3].workspace, 720)[0], 256)
        for slot, handle in first.items():
            self.assertEqual(
                struct.unpack_from('<Q', runs[1][3].workspace, 16480 + slot * 40)[0],
                handle)
        non_summary = lambda run: [(r[0], *r[2:]) for r in run[1] if r[0] != native.SUMMARY]
        self.assertEqual(non_summary(runs[0]), non_summary(runs[1]))

    def test_scalar_summary_cache_observes_live_container_again_after_preflight(self):
        results = []
        for summaries in (False, True):
            graph = [{'key': 1}]
            observer = native.ForeignGraphObserver()
            root = observer.register(graph)
            session = native.WireSession(
                self.image, observer, root, 4096, ensure_ascii=False, sort_keys=True,
                _builtin_keys=True, _immutable_summaries=summaries)
            original = session.observe
            changed = []
            container_requests = []
            def observe():
                opcode, sequence, phase = struct.unpack_from('<3Q', session.workspace, 8)
                handle, = struct.unpack_from('<Q', session.workspace, 200)
                if opcode == native.SUMMARY:
                    if type(observer.value(handle)) in (list, tuple, dict):
                        container_requests.append((handle, phase))
                    if phase == 101 and handle == root and not changed:
                        graph[0]['key'] = 999
                        graph.append({'later': '雪'})
                        changed.append(True)
                return original()
            session.observe = observe
            wire = session.run()
            self.assertEqual(changed, [True])
            self.assertEqual(wire, program_tools._reference_bounded_json_wire(
                graph, 4096, ensure_ascii=False, sort_keys=True))
            results.append((wire, container_requests))
        self.assertEqual(results[0], results[1])

    def test_summary_cache_budget_errors_unicode_and_slot_misses_match(self):
        cycle = []
        cycle.append(cycle)
        examples = [
            [{'same': 1}, {'same': 2, 'late': '\ud800'}],
            [{'same': 'x' * 256}, {'later': '\udfff'}],
            [{'same': 1}, cycle],
            {'same': float('nan')},
            {'same': float('inf')},
            {'a': {1: 0, '1': 1}},
            {'雪' * 32: 1, 'long-' + 'x' * 128: 2},
            {'nul': '\0' * 128, 'quote': '"\\\n'},
        ]
        for value in examples:
            for maximum in (0, 1, 2, 16, 128, 4096):
                self.compare_summaries(value, maximum, ensure_ascii=False, sort_keys=True)
        for ascii_flag in (False, True):
            value = [{'🧪': '雪', 'é': 123}] * 4
            expected = program_tools._reference_bounded_json_wire(
                value, 4096, ensure_ascii=ascii_flag, sort_keys=True)
            for maximum in (len(expected)-1, len(expected), len(expected)+1):
                self.compare_summaries(value, maximum, ensure_ascii=ascii_flag, sort_keys=True)

    def test_summary_capability_preserves_uncached_custom_transport(self):
        class Custom(native.ForeignGraphObserver):
            def summary(self, handle):
                return super().summary(handle)
        graph = [{'same': 1.25, 'text': '🧪'}] * 3
        for factory in (Custom, native.ForeignGraphObserver):
            runs = []
            for summaries in (False, True):
                observer = factory()
                if factory is native.ForeignGraphObserver:
                    original = observer.summary
                    observer.summary = lambda handle: original(handle)
                run = run_observed(self.image, graph, cache=True,
                                   summaries=summaries, observer=observer)
                self.assertFalse(run[3].summary_cache)
                self.assertFalse(run[3].key_cache)
                self.assertEqual(run[3]._protocol_magic, native.MAGIC)
                runs.append((run[0], run[1], bytes(run[3].workspace)))
            self.assertEqual(runs[0], runs[1])
        runs = []
        for summaries in (False, True):
            calls = []
            def render(value):
                calls.append(value)
                return '1.25'
            run = run_observed(self.image, graph, cache=True,
                               summaries=summaries, renderer=render)
            self.assertFalse(run[3].summary_cache)
            runs.append((run[0], run[1], calls, bytes(run[3].workspace)))
        self.assertEqual(runs[0], runs[1])
        with patch.object(sys, 'get_int_max_str_digits', lambda: 0):
            run = run_observed(self.image, graph, cache=True, summaries=True)
            self.assertFalse(run[3].summary_cache)

    def test_summary_protocol_refuses_malformed_and_replayed_acknowledgements(self):
        def fresh():
            observer = native.ForeignGraphObserver()
            return native.WireSession(
                self.image, observer, observer.register(123), 128,
                ensure_ascii=False, sort_keys=True, _builtin_keys=True,
                _immutable_summaries=True)
        for mutation in ('version', 'sequence', 'opcode', 'short', 'extra'):
            session = fresh()
            self.assertEqual(session.step(), 1)
            packet = bytearray(session.observe())
            before = bytes(session.workspace)
            if mutation == 'version':
                struct.pack_into('<Q', packet, 0, native.CACHED_MAGIC)
            elif mutation == 'sequence':
                struct.pack_into('<Q', packet, 8, 999)
            elif mutation == 'opcode':
                struct.pack_into('<Q', packet, 16, native.CHILD)
            elif mutation == 'short':
                packet.pop()
            else:
                packet.append(0)
            self.assertEqual(session.step(bytes(packet)), 199)
            self.assertEqual(bytes(session.workspace), before)
            with self.assertRaisesRegex(RuntimeError, 'terminal'):
                session.observe()
        session = fresh()
        self.assertEqual(session.step(), 1)
        packet = session.observe()
        self.assertEqual(session.step(packet), 1)
        before = bytes(session.workspace)
        self.assertEqual(session.step(packet), 199)
        self.assertEqual(bytes(session.workspace), before)


    def compare_paired_children(self, value, maximum=4096, **options):
        expected = outcome(lambda: program_tools._reference_bounded_json_wire(value, maximum, **options))
        old = run_observed(self.image, value, maximum, cache=True, summaries=True,
                           paired=False, **options)
        new = run_observed(self.image, value, maximum, cache=True, summaries=True,
                           paired=True, **options)
        self.assertEqual(old[0], expected)
        self.assertEqual(new[0], expected)
        self.assertFalse(old[3].paired_children)
        self.assertTrue(new[3].paired_children)
        def expanded(trace):
            result = []
            for opcode, sequence, handle, index, count, part in trace:
                if opcode == native.CHILD_PAIR:
                    self.assertEqual((count, part), (0, 0))
                    result.extend([(native.CHILD, handle, index, 0, 0),
                                   (native.CHILD, handle, index, 0, 1)])
                else:
                    result.append((opcode, handle, index, count, part))
            return result
        self.assertEqual(expanded(old[1]), expanded(new[1]))
        self.assertEqual(len(old[3].workspace), len(new[3].workspace))
        self.assertEqual(struct.unpack_from('<3Q', old[3].workspace, 712),
                         struct.unpack_from('<3Q', new[3].workspace, 712))
        return old, new

    def test_paired_children_preserve_bytes_and_every_foreign_observation(self):
        shared = {'z': [1, 2, 3], 'a': {'nested': '雪'}, 'quote"': True, 'x': None}
        examples = [
            shared, [shared, shared], {},
            {'🧪': 'é', 'A': '\n\0\\'},
            {2: 'two', -3: 'minus', 0.5: 'half'},
            {'left': [{'a': n, 'b': str(n)} for n in range(40)]},
            {'long' * 20: 1, 'short': [10000000000, -0.0, 1.25]},
        ]
        for value in examples:
            for ascii_flag in (False, True):
                for sort_flag in (False, True):
                    old, new = self.compare_paired_children(
                        value, 20000, ensure_ascii=ascii_flag, sort_keys=sort_flag)
                    if value:
                        self.assertGreater(sum(r[0] == native.CHILD_PAIR for r in new[1]), 0)
                    self.assertEqual(new[3]._protocol_magic, native.PAIRED_MAGIC)
                    self.assertEqual(old[3]._protocol_magic, native.SUMMARY_MAGIC)
                    self.assertEqual(len(old[1]) - len(new[1]),
                                     sum(r[0] == native.CHILD_PAIR for r in new[1]))

    def test_paired_children_keep_preflight_errors_and_value_order(self):
        cycle = []
        cycle.append(cycle)
        early = [
            {'a': {1: 0, '1': 1}},
            {'a': '\ud800', 'later': 2},
            {'a': cycle},
            {(1, 2): 3},
        ]
        for value in early:
            old, new = self.compare_paired_children(
                value, 4096, ensure_ascii=False, sort_keys=True)
            self.assertNotEqual(new[0][0], 'ok')
            self.assertFalse(any(r[0] == native.CHILD_PAIR for r in new[1]))
        late = [
            {'a': float('nan'), 'b': 2},
            {'a': float('inf'), 'b': [1, 2]},
            {'a': '\0' * 100, 'b': 'tail'},
        ]
        for value in late:
            for maximum in (0, 1, 2, 16, 128, 4096):
                for sort_flag in (False, True):
                    self.compare_paired_children(
                        value, maximum, ensure_ascii=False, sort_keys=sort_flag)
        # Every paired request is issued by an encoding phase. Preflight
        # still admits each key before requesting that entry's value.
        observer = native.ForeignGraphObserver()
        value = [{'a': 1, 'b': {'c': 2}}] * 2
        session = native.WireSession(
            self.image, observer, observer.register(value), 4096,
            ensure_ascii=False, sort_keys=True, _builtin_keys=True,
            _immutable_summaries=True, _paired_children=True)
        phases = []
        original = session.observe
        def observe():
            opcode, sequence, phase = struct.unpack_from('<3Q', session.workspace, 8)
            if opcode == native.CHILD_PAIR:
                phases.append(phase)
            return original()
        session.observe = observe
        self.assertEqual(session.run(), program_tools._reference_bounded_json_wire(
            value, 4096, ensure_ascii=False, sort_keys=True))
        self.assertTrue(phases)
        self.assertTrue(set(phases) <= {115, 145})

    def test_paired_children_capability_excludes_custom_and_older_profiles(self):
        graph = [{'a': 1, 'b': 2}] * 2
        for keys, summaries, paired, magic in [
                (False, False, True, native.MAGIC),
                (True, False, True, native.CACHED_MAGIC),
                (True, True, False, native.SUMMARY_MAGIC),
                (True, True, True, native.PAIRED_MAGIC)]:
            observer = native.ForeignGraphObserver()
            session = native.WireSession(
                self.image, observer, observer.register(graph), 4096,
                ensure_ascii=False, sort_keys=True, _builtin_keys=keys,
                _immutable_summaries=summaries, _paired_children=paired)
            self.assertEqual(session._protocol_magic, magic)
            self.assertEqual(session.run(), b'[{"a":1,"b":2},{"a":1,"b":2}]')
        class Custom(native.ForeignGraphObserver):
            def child(self, handle, index, part):
                return super().child(handle, index, part)
        for renderer in (None, lambda value: '1.5'):
            runs = []
            for paired in (False, True):
                result = run_observed(
                    self.image, graph, cache=True, summaries=True,
                    paired=paired, observer=Custom(), renderer=renderer)
                self.assertFalse(result[3].paired_children)
                self.assertEqual(result[3]._protocol_magic, native.MAGIC)
                runs.append((result[0], result[1], bytes(result[3].workspace)))
            self.assertEqual(runs[0], runs[1])

    def test_paired_children_acknowledgements_and_output_canaries(self):
        def fresh(sort_keys=True):
            observer = native.ForeignGraphObserver()
            session = native.WireSession(
                self.image, observer, observer.register({'a': 1, 'b': 2}), 128,
                ensure_ascii=False, sort_keys=sort_keys, _builtin_keys=True,
                _immutable_summaries=True, _paired_children=True)
            return session
        for sort_keys in (False, True):
            for mutation in ('version', 'sequence', 'opcode', 'short', 'extra'):
                session = fresh(sort_keys)
                while True:
                    self.assertEqual(session.step(), 1)
                    if struct.unpack_from('<Q', session.workspace, 8)[0] == native.CHILD_PAIR:
                        break
                    session.observe()
                packet = bytearray(session.observe())
                before = bytes(session.workspace)
                if mutation == 'version': struct.pack_into('<Q', packet, 0, native.SUMMARY_MAGIC)
                elif mutation == 'sequence': struct.pack_into('<Q', packet, 8, 0)
                elif mutation == 'opcode': struct.pack_into('<Q', packet, 16, native.CHILD)
                elif mutation == 'short': packet.pop()
                else: packet.append(0)
                self.assertEqual(session.step(bytes(packet)), 199)
                self.assertEqual(bytes(session.workspace), before)
                with self.assertRaisesRegex(RuntimeError, 'terminal'):
                    session.observe()
        for maximum in (0, 1, 2, 8, 128):
            observer = native.ForeignGraphObserver()
            session = native.WireSession(
                self.image, observer, observer.register({'a': 1}), maximum,
                ensure_ascii=False, sort_keys=True, _builtin_keys=True,
                _immutable_summaries=True, _paired_children=True)
            output = ctypes.create_string_buffer(maximum + 32)
            workspace = ctypes.create_string_buffer(len(session.workspace) + 32)
            ctypes.memset(output, 0xA5, len(output))
            ctypes.memset(workspace, 0xA5, len(workspace))
            size = len(session.workspace)
            session.output = ctypes.cast(ctypes.byref(output, 16), ctypes.POINTER(ctypes.c_char))
            session.workspace = (ctypes.c_char * size).from_buffer(workspace, 16)
            ctypes.memset(session.workspace, 0, size)
            outcome(session.run)
            self.assertEqual(output.raw[:16] + output.raw[-16:], b'\xa5' * 32)
            self.assertEqual(workspace.raw[:16] + workspace.raw[-16:], b'\xa5' * 32)

    def test_paired_child_transport_keeps_callback_order_and_once_consumption(self):
        # Mechanical transport control, deliberately separate from the
        # admitted ordinary observer/native execution tests above.
        for failing_part in (None, 0, 1):
            calls = []
            class Observer:
                def child(self, handle, index, part):
                    calls.append((handle, index, part))
                    if part == failing_part:
                        raise ValueError('mechanical observation failure')
                    return 11 + part
            session = object.__new__(native.WireSession)
            session.finished = False
            session._observation_pending = True
            session.paired_children = True
            session._protocol_magic = native.PAIRED_MAGIC
            session.workspace = ctypes.create_string_buffer(256)
            session.observer = Observer()
            session.packet = b'unchanged'
            struct.pack_into('<2Q', session.workspace, 8, native.CHILD_PAIR, 7)
            struct.pack_into('<4Q', session.workspace, 200, 3, 4, 0, 0)
            if failing_part is None:
                packet = session.observe()
                self.assertEqual(struct.unpack('<7Q', packet),
                                 (native.PAIRED_MAGIC, 7, native.CHILD_PAIR, 11, 12, 0, 0))
            else:
                with self.assertRaisesRegex(ValueError, 'mechanical observation failure'):
                    session.observe()
                self.assertEqual(session.packet, b'unchanged')
            self.assertEqual(calls, [(3, 4, 0)] if failing_part == 0 else [(3, 4, 0), (3, 4, 1)])
            with self.assertRaisesRegex(RuntimeError, 'no unconsumed observation'):
                session.observe()
