"""Protocol 04 controls; legacy 02/03 remain separately exercised.

The source class executes HIA through the Core interpreter only. The native
class requires the original explicit cold/development fixture and never treats
its absence as qualification. Request comparisons retain phase and handle so
value/container observations cannot disappear under a key-cache assertion.
"""
from __future__ import annotations

import ast
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

FIXTURE_EVIDENCE = 'HEPTA_HIA_JSON_WIRE_KEY_SUMMARY_FIXTURE_EVIDENCE'
KEY_REPLY_PHASES = (12, 15, 114, 143)


def _observed(image, value, maximum=256, *, protocol, ensure_ascii=False,
              sort_keys=True, observer=None, renderer=None):
    observer = native.ForeignGraphObserver() if observer is None else observer
    session = native.WireSession(image, observer, observer.register(value), maximum,
        ensure_ascii=ensure_ascii, sort_keys=sort_keys, float_renderer=renderer,
        _builtin_keys=protocol in (3, 4), _builtin_key_summaries=protocol == 4)
    trace = []
    original_step = session.step

    def step(packet=None):
        status = original_step(packet)
        if status == 1:
            opcode, sequence, phase = struct.unpack_from('<3Q', session.workspace, 8)
            request = struct.unpack_from('<4Q', session.workspace, 200)
            trace.append((opcode, sequence, *request, phase))
        return status

    session.step = step
    result = base_tests.outcome(session.run)
    cached = {}
    base, = struct.unpack_from('<Q', session.workspace, 648)
    if base:
        for index in range(1024):
            handle, size, count, width = struct.unpack_from('<4Q', session.workspace, base + index * 160)
            if handle:
                cached[handle] = (size, count, width)
    return {'outcome': result, 'trace': trace, 'session': session, 'observer': observer,
            'cached': cached, 'text_counts': struct.unpack_from('<3Q', session.workspace, 656),
            'summary_counts': struct.unpack_from('<2Q', session.workspace, 696)}


def _check_summary_projection(case, legacy, current):
    """Every removed request must be a later admitted exact-string KEY summary."""
    case.assertEqual(current['outcome'], legacy['outcome'])
    case.assertEqual(current['text_counts'], legacy['text_counts'])
    case.assertEqual(current['cached'], legacy['cached'])
    for result in (legacy, current):
        case.assertEqual([row[1] for row in result['trace']], list(range(1, len(result['trace']) + 1)))
    position = 0
    seen_summary = set()
    omitted = []
    for old in legacy['trace']:
        target = current['trace'][position] if position < len(current['trace']) else None
        normalized = (old[0], *old[2:])
        if target is not None and normalized == (target[0], *target[2:]):
            position += 1
            if old[0] == native.SUMMARY:
                seen_summary.add(old[2])
            continue
        case.assertEqual(old[0], native.SUMMARY)
        case.assertIn(old[-1], KEY_REPLY_PHASES)
        handle = old[2]
        case.assertIn(handle, seen_summary)
        case.assertIn(handle, current['cached'])
        value = current['observer'].value(handle)
        case.assertIs(type(value), str)
        case.assertLessEqual(len(value), 32)
        case.assertEqual(current['cached'][handle][0], len(value))
        omitted.append(old)
    case.assertEqual(position, len(current['trace']))
    case.assertEqual(current['summary_counts'][0], len(omitted))
    return omitted


class _CoreImage(native.NativeJsonWire):
    def __init__(self, program):
        self.program = program
        self.calls = 0

    def _entry(self, source, source_size, output, output_size, workspace, workspace_size):
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        owners = [_Owner(-1, bytearray(ctypes.string_at(source, source_size))),
                  _Owner(-2, bytearray(ctypes.string_at(output, output_size))),
                  _Owner(-3, bytearray(ctypes.string_at(workspace, workspace_size)))]
        machine = _Machine(self.program, 10000000, 64 << 20, None, 128)
        returned = machine.invoke(self.program.as_dict()['functions'][0],
            [_View(owners[0], False), _View(owners[1], True), _View(owners[2], True)])[0]
        ctypes.memmove(output, bytes(owners[1].data), output_size)
        ctypes.memmove(workspace, bytes(owners[2].data), workspace_size)
        self.calls += 1
        return returned


class WireKeySummarySourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from hepta.hia_agent_assembly import assemble_program
        from tools.generate_hia_json_wire import source_program
        cls.program = assemble_program(native.SOURCE.read_bytes())
        names = {node.name: 'f' + str(index)
                 for index, node in enumerate(ast.parse(source_program()).body)}
        functions = {fn['name']: fn for fn in cls.program.as_dict()['functions']}
        cls.functions = {name: functions[symbol] for name, symbol in names.items()}

    def invoke(self, name, workspace, scalars=(), source=None):
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        owner = _Owner(-1, bytearray(workspace))
        args = [_View(owner, True)]
        if source is not None:
            args.insert(0, _View(_Owner(-2, bytearray(source)), False))
        machine = _Machine(self.program, 10000000, 64 << 20, None, 128)
        result = machine.invoke(self.functions[name], args + list(scalars))
        self.assertEqual(len(result), 1)
        return result[0], owner.data

    def test_generated_source_and_versioned_fixed_memory_extent(self):
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        from tools.generate_hia_json_wire import document, FIELDS
        doc = document()
        assembly = render_assembly(doc).encode()
        self.assertEqual(native.SOURCE.read_bytes(), assembly)
        self.assertEqual(assemble_program(assembly).as_dict(), doc)
        self.assertLessEqual(len(assembly), 1 << 20)
        self.assertLessEqual(len(assembly.splitlines()), 16384)
        self.assertLessEqual(len(doc['functions']), 128)
        self.assertLessEqual(sum(len(fn['blocks']) for fn in doc['functions']), 1536)
        self.assertLessEqual(sum(len(block['ops']) for fn in doc['functions'] for block in fn['blocks']), 8192)
        for fn in doc['functions']:
            self.assertLessEqual(len(fn['params']), 16)
            self.assertLessEqual(len(fn['returns']), 3)
            self.assertLessEqual(len(fn['blocks']), 256)
            names = {param['name'] for param in fn['params']}
            for block in fn['blocks']:
                self.assertLessEqual(len(block['params']), 16)
                names.update(param['name'] for param in block['params'])
                for operation in block['ops']:
                    self.assertLessEqual(len(operation['args']), 16)
                    self.assertLessEqual(len(operation['out']), 3)
                    names.update(result['name'] for result in operation['out'])
                term = block['term']
                for edge in ('then', 'else'):
                    if edge in term:
                        self.assertLessEqual(len(term[edge]['args']), 16)
                self.assertLessEqual(len(term.get('args', [])), 16)
                self.assertLessEqual(len(term.get('values', [])), 16)
            self.assertLessEqual(len(names), 2048)
        self.assertEqual((native.MAGIC, native.CACHED_MAGIC, native.KEY_SUMMARY_MAGIC),
                         tuple(int.from_bytes(magic, 'little') for magic in (b'HIAWIR02', b'HIAWIR03', b'HIAWIR04')))
        self.assertEqual([FIELDS[name] for name in ('KEY_SUMMARY_READY', 'KEY_SUMMARY_SIZE',
                         'KEY_SUMMARY_HITS', 'KEY_SUMMARY_MISSES')], [680, 688, 696, 704])
        self.assertEqual(native.KEY_CACHE_BYTES, 163840)
        for maximum in (0, 1, 128, native.MAXIMUM):
            self.assertEqual(native.buffer_sizes(maximum, key_cache=True)[1]
                             - native.buffer_sizes(maximum)[1], 163840)

    def test_core_key_summary_hit_and_miss_preserve_legacy_request_bytes(self):
        from tools.generate_hia_json_wire import FIELDS
        base = 1024
        handle = 7
        slot = base + handle * 160
        for magic in (native.MAGIC, native.CACHED_MAGIC, native.KEY_SUMMARY_MAGIC):
            for variant in ('valid', 'absent', 'collision', 'long', 'bad_count', 'bad_width'):
                with self.subTest(magic=magic, variant=variant):
                    workspace = bytearray(4096)
                    values = {0: magic, 16: 11, 32: 128, 648: base, 680: 13, 688: 17,
                              696: 19, 704: 23, 200: 29, 208: 31, 216: 37, 224: 41,
                              slot: handle, slot + 8: 4, slot + 16: 4, slot + 24: 6}
                    if variant == 'absent': values[slot] = 0
                    if variant == 'collision': values[slot] = handle + 1024
                    if variant == 'long': values[slot + 8] = 33
                    if variant == 'bad_count': values[slot + 16] = 129
                    if variant == 'bad_width': values[slot + 24] = 129
                    for offset, value in values.items():
                        struct.pack_into('<Q', workspace, offset, value)
                    expected = bytearray(workspace)
                    hit = magic == native.KEY_SUMMARY_MAGIC and variant == 'valid'
                    if magic == native.KEY_SUMMARY_MAGIC:
                        struct.pack_into('<Q', expected, 680, int(hit))
                        struct.pack_into('<Q', expected, 696 if hit else 704, 20 if hit else 24)
                        if hit:
                            struct.pack_into('<Q', expected, 688, 4)
                    if hit:
                        struct.pack_into('<Q', expected, 24, 143)
                    else:
                        for offset, value in ((16, 12), (8, 1), (200, handle), (208, 0),
                                              (216, 0), (224, 0), (24, 143)):
                            struct.pack_into('<Q', expected, offset, value)
                    status, actual = self.invoke('key_summary', workspace, [handle, 143])
                    self.assertEqual(status, 0 if hit else 1)
                    self.assertEqual(actual, expected)

    def test_core_cached_facts_do_not_consume_the_previous_child_packet(self):
        source = struct.pack('<7Q', native.KEY_SUMMARY_MAGIC, 11, native.CHILD, 9, 13, 17, 19)
        for magic in (native.MAGIC, native.CACHED_MAGIC, native.KEY_SUMMARY_MAGIC):
            for ready in (0, 1):
                workspace = bytearray(1024)
                for offset, value in ((0, magic), (680, ready), (688, 3)):
                    struct.pack_into('<Q', workspace, offset, value)
                cached = magic == native.KEY_SUMMARY_MAGIC and ready == 1
                for offset, expected in zip((24, 32, 40, 48), (4, 3, 0, 0) if cached else (9, 13, 17, 19)):
                    with self.subTest(magic=magic, ready=ready, offset=offset):
                        # A hit must not read even one byte from the old packet.
                        result, actual = self.invoke('key_fact', workspace, [offset], b'' if cached else source)
                        self.assertEqual(result, expected)
                        self.assertEqual(actual, workspace)
                expected = bytearray(workspace)
                facts = (4, 3, 0, 0) if cached else (9, 13, 17, 19)
                for offset, value in ((328, 7), (336, facts[0]), (344, facts[1]), (352, facts[2]),
                                      (360, facts[3]), (368, 3), (376, 512), (384, 144),
                                      (392, 0), (424, 0), (24, 20)):
                    struct.pack_into('<Q', expected, offset, value)
                result, actual = self.invoke('key_norm_begin', workspace, [7, 3, 512, 144], b'' if cached else source)
                self.assertEqual(result, 0)
                self.assertEqual(actual, expected)

    def test_core_protocol04_only_removes_admitted_key_summaries(self):
        image = _CoreImage(self.program)
        key = 'key'
        graph = [{key: key}, {key: 1}]
        old = _observed(image, graph, protocol=3)
        new = _observed(image, graph, protocol=4)
        self.assertEqual(old['outcome'], ('ok', b'[{"key":"key"},{"key":1}]'))
        omitted = _check_summary_projection(self, old, new)
        self.assertGreater(len(omitted), 0)
        self.assertTrue(all(row[-1] in KEY_REPLY_PHASES for row in omitted))
        self.assertGreater(image.calls, 0)
        value_requests = [(row[0], *row[2:]) for row in new['trace']
                          if row[0] == native.SUMMARY and row[-1] in (2, 101)]
        self.assertEqual(value_requests, [(row[0], *row[2:]) for row in old['trace']
                         if row[0] == native.SUMMARY and row[-1] in (2, 101)])

    def test_bridge_capability_and_fresh_sessions_do_not_share_cached_facts(self):
        image = object()  # No entry is called by this shape/lifetime control.
        key = 'same'
        sessions = []
        for protocol in (2, 3, 4, 4):
            observer = native.ForeignGraphObserver()
            session = native.WireSession(image, observer, observer.register({key: 1}), 128,
                ensure_ascii=False, sort_keys=True, _builtin_keys=protocol != 2,
                _builtin_key_summaries=protocol == 4)
            sessions.append(session)
            self.assertEqual(session._protocol_magic, (native.MAGIC, native.CACHED_MAGIC,
                             native.KEY_SUMMARY_MAGIC)[protocol - 2])
            self.assertEqual(bytes(session.workspace), b'\0' * len(session.workspace))
        self.assertIsNot(sessions[2].observer, sessions[3].observer)
        self.assertIsNot(sessions[2].workspace, sessions[3].workspace)
        struct.pack_into('<Q', sessions[2].workspace, 696, 1)
        self.assertEqual(struct.unpack_from('<Q', sessions[3].workspace, 696)[0], 0)
        observer = native.ForeignGraphObserver()
        observer.summary = lambda handle: (4, 0, 0, 0)
        session = native.WireSession(image, observer, observer.register(key), 128,
            ensure_ascii=False, sort_keys=True, _builtin_keys=True, _builtin_key_summaries=True)
        self.assertFalse(session.key_cache)
        self.assertFalse(session.key_summary_cache)
        self.assertEqual(session._protocol_magic, native.MAGIC)

    def test_core_legacy_magic_and_protocol04_packet_boundaries(self):
        image = _CoreImage(self.program)
        for packet_size in (104, 112):
            observer = native.ForeignGraphObserver()
            session = native.WireSession(image, observer, observer.register({'a': 1}), 128,
                ensure_ascii=False, sort_keys=True, _builtin_keys=True, _builtin_key_summaries=True)
            packet = bytearray(session.packet[:packet_size])
            struct.pack_into('<Q', packet, 0, int.from_bytes(b'HIAWIR01', 'little'))
            self.assertEqual(session.step(bytes(packet)), 199)
            with self.assertRaisesRegex(RuntimeError, 'terminal'):
                session.observe()
        observer = native.ForeignGraphObserver()
        session = native.WireSession(image, observer, observer.register({'a': 1}), 128,
            ensure_ascii=False, sort_keys=True, _builtin_keys=True, _builtin_key_summaries=True)
        self.assertEqual(session.step(), 1)
        reply = bytearray(session.observe())
        struct.pack_into('<Q', reply, 0, native.CACHED_MAGIC)
        self.assertEqual(session.step(bytes(reply)), 199)
        with self.assertRaisesRegex(RuntimeError, 'terminal'):
            session.observe()
        for mutation in ('cap0', 'cap2', 'short', 'long', 'renderer'):
            observer = native.ForeignGraphObserver()
            session = native.WireSession(image, observer, observer.register({'a': 1}), 128,
                ensure_ascii=False, sort_keys=True, _builtin_keys=True, _builtin_key_summaries=True)
            packet = bytearray(session.packet)
            if mutation == 'cap0': struct.pack_into('<Q', packet, 104, 0)
            if mutation == 'cap2': struct.pack_into('<Q', packet, 104, 2)
            if mutation == 'short': packet.pop()
            if mutation == 'long': packet.append(0)
            if mutation == 'renderer': struct.pack_into('<Q', packet, 96, 1)
            with self.subTest(mutation=mutation):
                self.assertEqual(session.step(bytes(packet)), 199)


class WireKeySummaryNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        evidence = os.environ.get(FIXTURE_EVIDENCE, '')
        with patch.dict(os.environ, {base_tests.FIXTURE_EVIDENCE: evidence}):
            base_tests.WireNativeTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        base_tests.WireNativeTests.tearDownClass.__func__(cls)

    def compare(self, value, maximum=4096, **options):
        expected = base_tests.outcome(lambda: program_tools._reference_bounded_json_wire(value, maximum, **options))
        old = _observed(self.image, value, maximum, protocol=3, **options)
        new = _observed(self.image, value, maximum, protocol=4, **options)
        self.assertEqual(old['outcome'], expected)
        omitted = _check_summary_projection(self, old, new)
        return old, new, omitted

    def test_repeated_keys_keep_every_value_child_and_sort_observation(self):
        keys = ('gamma', 'alpha', 'beta', '', '雪', '🧪', 'quote"slash\\')
        shared = {key: key for key in keys}
        for ascii_flag in (False, True):
            for sort_flag in (False, True):
                with self.subTest(ascii=ascii_flag, sort=sort_flag):
                    old, new, omitted = self.compare([shared, dict(shared), shared],
                        ensure_ascii=ascii_flag, sort_keys=sort_flag)
                    self.assertGreater(len(omitted), 0)
                    self.assertLess(len(new['trace']), len(old['trace']))
                    self.assertTrue(new['session'].key_summary_cache)
                    self.assertEqual(new['session']._protocol_magic, native.KEY_SUMMARY_MAGIC)

    def test_cache_capacity_collision_and_long_keys_fall_back(self):
        keys = ['key-' + str(index).zfill(4) for index in range(1025)]
        graph = {key: 0 for key in keys}
        results = []
        for protocol in (3, 4):
            observer = native.ForeignGraphObserver()
            for index, key in enumerate(keys, 1):
                self.assertEqual(observer.register(key), index)
            results.append(_observed(self.image, graph, 230000, protocol=protocol, observer=observer))
        omitted = _check_summary_projection(self, *results)
        self.assertGreater(len(omitted), 0)
        self.assertEqual(results[1]['text_counts'][2], 1024)
        self.assertIn(1, results[1]['cached'])
        self.assertNotIn(1025, results[1]['cached'])
        self.assertTrue(any(row[0] == native.SUMMARY and row[2] == 1025
                            for row in results[1]['trace']))
        long_key = '雪' * 33
        _, result, _ = self.compare([{'a' * 32: 0, long_key: 1}, {long_key: 2}],
                                   ensure_ascii=False, sort_keys=True)
        self.assertTrue(all(len(result['observer'].value(handle)) <= 32 for handle in result['cached']))

    def test_budget_unicode_collision_and_failure_order_are_unchanged(self):
        cycle = []
        cycle.append(cycle)
        class Text(str):
            def __len__(self):
                raise AssertionError('foreign subtype length')
        values = [[{'same': 1}, {'same': 2, 'later': '\ud800'}],
                  [{'same': 'x' * 256}, {'later': '\ud800'}],
                  [{'same': 1}, cycle], {'same': float('nan')},
                  {'a': {1: 0, '1': 1}}, {Text('same'): 1},
                  {'🧪' * 32: 1}, {None: 1, 'null': 2},
                  [{True: 1, 2.5: 2}, {'true': 3, '2.5': 4}]]
        for value in values:
            for maximum in (0, 1, 2, 16, 128, 4096):
                with self.subTest(kind=type(value).__name__, maximum=maximum):
                    self.compare(value, maximum, ensure_ascii=False, sort_keys=True)
        for extra in (0, 1):
            self.compare({'cache': 'x' * (230000 - 12 + extra)}, 230000,
                         ensure_ascii=False, sort_keys=True)

    def test_foreign_renderer_and_replaced_observer_keep_legacy_protocol(self):
        class Custom(native.ForeignGraphObserver):
            pass
        graph = [{'b': 1.5, 'a': 2}] * 3
        for mode in ('subclass', 'instance', 'class', 'digit_limit', 'renderer'):
            results = []
            calls = []
            def render(number):
                calls.append(number)
                return '1.5'
            original = native.ForeignGraphObserver.summary
            for protocol in (2, 4):
                observer = Custom() if mode == 'subclass' else native.ForeignGraphObserver()
                if mode == 'instance':
                    observer.summary = lambda handle, observer=observer: original(observer, handle)
                with patch.object(native.ForeignGraphObserver, 'summary',
                        (lambda self, handle: original(self, handle)) if mode == 'class' else original), \
                        patch.object(sys, 'get_int_max_str_digits',
                        (lambda: 0) if mode == 'digit_limit' else sys.get_int_max_str_digits):
                    result = _observed(self.image, graph, protocol=protocol, observer=observer,
                                       renderer=render if mode == 'renderer' else None)
                self.assertEqual(result['session']._protocol_magic, native.MAGIC)
                self.assertFalse(result['session'].key_summary_cache)
                results.append((result['outcome'], result['trace'], bytes(result['session'].workspace)))
            self.assertEqual(results[0], results[1])
            if mode == 'renderer': self.assertEqual(calls, [1.5] * 6)

    def test_protocol04_rejects_cross_version_ack_and_preserves_canaries(self):
        def session(maximum=128):
            observer = native.ForeignGraphObserver()
            return native.WireSession(self.image, observer, observer.register({'a': 1}), maximum,
                ensure_ascii=False, sort_keys=True, _builtin_keys=True, _builtin_key_summaries=True)
        for packet_size in (104, 112):
            value = session()
            packet = bytearray(value.packet[:packet_size])
            struct.pack_into('<Q', packet, 0, int.from_bytes(b'HIAWIR01', 'little'))
            self.assertEqual(value.step(bytes(packet)), 199)
            with self.assertRaisesRegex(RuntimeError, 'terminal'):
                value.observe()
        for wrong_magic in (native.MAGIC, native.CACHED_MAGIC):
            value = session()
            self.assertEqual(value.step(), 1)
            reply = bytearray(value.observe())
            with self.assertRaisesRegex(RuntimeError, 'no unconsumed observation'):
                value.observe()
            struct.pack_into('<Q', reply, 0, wrong_magic)
            self.assertEqual(value.step(bytes(reply)), 199)
            with self.assertRaisesRegex(RuntimeError, 'terminal'):
                value.step()
        for maximum in (0, 1, 2, 16, 128):
            value = session(maximum)
            output = ctypes.create_string_buffer(maximum + 32)
            workspace = ctypes.create_string_buffer(len(value.workspace) + 32)
            ctypes.memset(output, 0xa5, len(output))
            ctypes.memset(workspace, 0xa5, len(workspace))
            size = len(value.workspace)
            value.output = ctypes.cast(ctypes.byref(output, 16), ctypes.POINTER(ctypes.c_char))
            value.workspace = (ctypes.c_char * size).from_buffer(workspace, 16)
            ctypes.memset(value.workspace, 0, size)
            base_tests.outcome(value.run)
            self.assertEqual(output.raw[:16] + output.raw[-16:], b'\xa5' * 32)
            self.assertEqual(workspace.raw[:16] + workspace.raw[-16:], b'\xa5' * 32)

    def test_ordinary_entry_has_fresh_cache_and_no_host_encoder(self):
        value = [{'b': 1, 'a': 2}] * 4
        expected = program_tools._reference_bounded_json_wire(value, 4096, ensure_ascii=False)
        seen = []
        original_run = native.WireSession.run
        def run(session):
            seen.append(session)
            self.assertEqual(bytes(session.workspace), b'\0' * len(session.workspace))
            return original_run(session)
        with patch.object(native.WireSession, 'run', run), \
                patch.object(program_tools, '_reference_bounded_json_wire', side_effect=AssertionError('retained owner entered')), \
                patch.object(json.JSONEncoder, 'iterencode', side_effect=AssertionError('host encoder entered')):
            for _ in range(2):
                self.assertEqual(self.image.encode_ordinary(value, 4096, ensure_ascii=False), expected)
        self.assertEqual(len(seen), 2)
        self.assertIsNot(seen[0].observer, seen[1].observer)
        self.assertIsNot(seen[0].workspace, seen[1].workspace)
        for session in seen:
            self.assertTrue(session.key_summary_cache)
            self.assertEqual(session._protocol_magic, native.KEY_SUMMARY_MAGIC)
            self.assertGreater(struct.unpack_from('<Q', session.workspace, 696)[0], 0)
