"""Protocol05 immutable-leaf controls; the original02/03/04 methods stay intact.

Source controls use the existing Core image and small direct helper calls.
Native controls require the existing explicit cold/development fixture.  The
request projection compares every retained request and reply byte apart from
the explicitly versioned magic and monotonically renumbered sequence fields.
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
from tests import test_hia_json_wire_key_summary as key_tests

FIXTURE_EVIDENCE = 'HEPTA_HIA_JSON_WIRE_LEAF_CACHE_FIXTURE_EVIDENCE'
VALUE_PHASES = (2, 101)


def _u64(data, offset):
    return struct.unpack_from('<Q', data, offset)[0]


def _put(data, pairs):
    for offset, value in pairs:
        struct.pack_into('<Q', data, offset, value)


def _session(image, value, maximum=128, *, protocol=5, ensure_ascii=False,
             sort_keys=True, observer=None, renderer=None):
    observer = native.ForeignGraphObserver() if observer is None else observer
    return native.WireSession(image, observer, observer.register(value), maximum,
        ensure_ascii=ensure_ascii, sort_keys=sort_keys, float_renderer=renderer,
        _builtin_keys=protocol >= 3, _builtin_key_summaries=protocol >= 4,
        _builtin_leaves=protocol == 5)


def _capture(image, value, maximum=4096, *, protocol, ensure_ascii=False,
             sort_keys=True, observer=None, renderer=None):
    session = _session(image, value, maximum, protocol=protocol,
        ensure_ascii=ensure_ascii, sort_keys=sort_keys, observer=observer, renderer=renderer)
    trace = []
    original_step, original_observe = session.step, session.observe

    def step(packet=None):
        status = original_step(packet)
        if type(status) is not int:
            raise AssertionError('native wire status must be an exact integer')
        if status == 1:
            opcode, sequence, phase = struct.unpack_from('<3Q', session.workspace, 8)
            handle, index, count, part = struct.unpack_from('<4Q', session.workspace, 200)
            trace.append({'request': (opcode, sequence, handle, index, count, part, phase),
                          'text_mode': _u64(session.workspace, 448) if opcode == native.POINTS else None,
                          'reply': None})
        return status

    def observe():
        packet = original_observe()
        trace[-1]['reply'] = packet
        return packet

    session.step, session.observe = step, observe
    result = base_tests.outcome(session.run)
    key_rows, leaves = {}, {}
    key_base = _u64(session.workspace, 648)
    if key_base:
        for index in range(1024):
            slot = key_base + index * 160
            handle, size, count, width = struct.unpack_from('<4Q', session.workspace, slot)
            if handle:
                key_rows[handle] = (size, count, width,
                                    bytes(session.workspace[slot + 32:slot + 32 + count]))
    if session._protocol_magic == native.LEAF_MAGIC:
        leaf_base = _u64(session.workspace, 712)
        if leaf_base:
            for index in range(1024):
                slot = leaf_base + index * 304
                row = struct.unpack_from('<6Q', session.workspace, slot)
                if row[0]:
                    leaves[row[0]] = (row[1:], bytes(session.workspace[slot + 48:slot + 304]))
    return {'outcome': result, 'trace': trace, 'session': session,
            'observer': session.observer, 'maximum': maximum, 'ascii': ensure_ascii,
            'key_rows': key_rows, 'leaves': leaves,
            'key_counts': struct.unpack_from('<3Q', session.workspace, 656),
            'key_summary_counts': struct.unpack_from('<2Q', session.workspace, 696),
            'leaf_hits': _u64(session.workspace, 728), 'point_hits': _u64(session.workspace, 760)}


def _width(point, ascii_flag):
    if point < 32:
        return 2 if point in (8, 9, 10, 12, 13) else 6
    if point in (34, 92):
        return 2
    if point < 128:
        return 6 if point == 127 and ascii_flag else 1
    if ascii_flag:
        return 6 if point <= 65535 else 12
    return 2 if point < 2048 else 3 if point < 65536 else 4


def _projection(case, old, current):
    """04 ->05 permits only already-admitted immutable VALUE observations."""
    case.assertEqual(old['outcome'], current['outcome'])
    case.assertEqual(old['key_rows'], current['key_rows'])
    case.assertEqual(old['key_counts'], current['key_counts'])
    case.assertEqual(old['key_summary_counts'], current['key_summary_counts'])
    case.assertEqual(set(old['observer']._objects), set(current['observer']._objects))
    for handle, value in old['observer']._objects.items():
        case.assertIs(value, current['observer']._objects[handle])
    for result in (old, current):
        case.assertEqual([row['request'][1] for row in result['trace']],
                         list(range(1, len(result['trace']) + 1)))
    admitted, pending, omitted = {}, {}, []
    position = 0

    def remember(row):
        opcode, _, handle, index, count, part, phase = row['request']
        reply = row['reply']
        if reply is None:
            return
        words = struct.unpack_from('<7Q', reply)
        if opcode == native.SUMMARY and phase == 2:
            value = old['observer'].value(handle)
            kind, size = words[3:5]
            if ((kind == 0 and value is None)
                    or (kind == 1 and type(value) is bool)
                    or (kind == 2 and type(value) is int and size <= old['maximum'] * 4)
                    or (kind == 3 and type(value) is float)):
                admitted.setdefault(handle, {'facts': reply[24:56], 'points': None})
            elif (kind == 4 and type(value) is str and size == len(value)
                    and old['maximum'] >= 2 and size <= old['maximum'] - 2):
                if size == 0:
                    admitted.setdefault(handle, {'facts': reply[24:56], 'points': ()})
                else:
                    pending.setdefault(handle, {'facts': reply[24:56], 'size': size, 'points': []})
        elif opcode == native.POINTS and phase == 31 and row['text_mode'] == 0 and handle in pending:
            item = pending[handle]
            case.assertEqual(index, len(item['points']))
            case.assertEqual(words[3], count)
            points = struct.unpack('<' + 'I' * count, reply[56:])
            item['points'].extend(points)
            case.assertLessEqual(len(item['points']), item['size'])
            if len(item['points']) == item['size']:
                valid = (all(0 <= p <= 0x10ffff and not 0xd800 <= p <= 0xdfff for p in item['points'])
                         and 2 + sum(_width(p, old['ascii']) for p in item['points']) <= old['maximum'])
                if valid:
                    admitted.setdefault(handle, {'facts': item['facts'], 'points': tuple(item['points'])})
                del pending[handle]

    for row in old['trace']:
        request = row['request']
        target = current['trace'][position] if position < len(current['trace']) else None
        same = (target is not None and (request[0], *request[2:]) ==
                (target['request'][0], *target['request'][2:]))
        if same:
            case.assertEqual(row['text_mode'], target['text_mode'])
            if row['reply'] is None or target['reply'] is None:
                case.assertIs(row['reply'], target['reply'])
            else:
                # Magic and sequence are deliberately versioned; opcode and
                # the complete facts/payload of every retained reply are exact.
                case.assertEqual(row['reply'][16:], target['reply'][16:])
            remember(row)
            position += 1
            continue
        opcode, _, handle, index, count, part, phase = request
        case.assertIsNotNone(row['reply'])
        case.assertIn(handle, admitted)
        case.assertIn(handle, current['leaves'])
        value = old['observer'].value(handle)
        case.assertTrue(value is None or type(value) in (bool, int, float, str))
        if opcode == native.SUMMARY:
            case.assertIn(phase, VALUE_PHASES)
            case.assertEqual((index, count, part), (0, 0, 0))
            case.assertEqual(row['reply'][24:56], admitted[handle]['facts'])
        else:
            case.assertEqual(opcode, native.POINTS)
            case.assertEqual(phase, 31)
            case.assertIn(row['text_mode'], (0, 3))
            case.assertIs(type(value), str)
            case.assertLessEqual(len(value), 64)
            points = admitted[handle]['points']
            case.assertIsNotNone(points)
            case.assertEqual(part, 0)
            case.assertLessEqual(index + count, len(points))
            case.assertEqual(row['reply'][56:],
                             struct.pack('<' + 'I' * count, *points[index:index + count]))
        omitted.append(row)
    case.assertEqual(position, len(current['trace']))
    case.assertEqual(current['leaf_hits'], sum(row['request'][0] == native.SUMMARY for row in omitted))
    # Empty strings can hit the points cache without having any POINTS request.
    case.assertGreaterEqual(current['point_hits'],
                            sum(row['request'][0] == native.POINTS for row in omitted))
    protected = (native.CHILD, native.LIMBS, native.DIGIT_LIMIT, native.FORMAT_FLOAT)
    for opcode in protected:
        case.assertEqual([(r['request'][0], *r['request'][2:], r['reply'][16:] if r['reply'] else None)
                          for r in old['trace'] if r['request'][0] == opcode],
                         [(r['request'][0], *r['request'][2:], r['reply'][16:] if r['reply'] else None)
                          for r in current['trace'] if r['request'][0] == opcode])
    return omitted


def _packet_boundaries(case, image):
    for mutation in ('cap0', 'cap2', 'short', 'long', 'cross_magic', 'renderer', 'small_workspace'):
        session = _session(image, {'a': 1}, 16)
        packet = bytearray(session.packet)
        workspace_size = len(session.workspace)
        if mutation == 'cap0': struct.pack_into('<Q', packet, 104, 0)
        if mutation == 'cap2': struct.pack_into('<Q', packet, 104, 2)
        if mutation == 'short': packet.pop()
        if mutation == 'long': packet.append(0)
        if mutation == 'cross_magic': struct.pack_into('<Q', packet, 0, native.MAGIC)
        if mutation == 'renderer': struct.pack_into('<Q', packet, 96, 1)
        if mutation == 'small_workspace': workspace_size -= 1
        buffers = [ctypes.create_string_buffer(size + 32)
                   for size in (len(packet), 16, workspace_size)]
        for buffer in buffers:
            ctypes.memset(buffer, 0xa5, len(buffer))
        pointers = [ctypes.cast(ctypes.byref(buffer, 16), ctypes.c_void_p) for buffer in buffers]
        ctypes.memmove(pointers[0], bytes(packet), len(packet))
        ctypes.memset(pointers[1], 0, 16)
        ctypes.memset(pointers[2], 0, workspace_size)
        before = [bytes(buffer) for buffer in buffers]
        with case.subTest(mutation=mutation):
            status = image._entry(pointers[0], len(packet), pointers[1], 16,
                                  pointers[2], workspace_size)
            case.assertEqual(status, 199)
            case.assertEqual([bytes(buffer) for buffer in buffers], before)
    session = _session(image, {'a': 1}, 128)
    case.assertEqual(session.step(), 1)
    reply = bytearray(session.observe())
    with case.assertRaisesRegex(RuntimeError, 'no unconsumed observation'):
        session.observe()
    struct.pack_into('<Q', reply, 0, native.KEY_SUMMARY_MAGIC)
    case.assertEqual(session.step(bytes(reply)), 199)
    with case.assertRaisesRegex(RuntimeError, 'terminal'):
        session.observe()
    with case.assertRaisesRegex(RuntimeError, 'terminal'):
        session.step()


class WireLeafCacheSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        key_tests.WireKeySummarySourceTests.setUpClass.__func__(cls)

    invoke = key_tests.WireKeySummarySourceTests.invoke

    def text_step(self, workspace, source, phase):
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        inputs = _Owner(-1, bytearray(source))
        output = _Owner(-2, bytearray(512))
        work = _Owner(-3, bytearray(workspace))
        machine = _Machine(self.program, 10000000, 64 << 20, None, 128)
        returned = machine.invoke(self.functions['leaf_normalize'],
            [_View(inputs, False), _View(output, True), _View(work, True), phase])
        self.assertEqual(len(returned), 1)
        self.assertEqual(inputs.data, source)
        return returned[0], work.data, output.data

    def test_01_generated_source_original_nine_caps_and_disjoint_extent(self):
        # This is the unchanged existing source-cap method, not weakened caps.
        key_tests.WireKeySummarySourceTests.test_generated_source_and_versioned_fixed_memory_extent(self)
        from tools.generate_hia_json_wire import FIELDS
        self.assertEqual(native.LEAF_MAGIC, int.from_bytes(b'HIAWIR05', 'little'))
        self.assertEqual(native.LEAF_CACHE_BYTES, 1024 * 304)
        self.assertEqual([FIELDS[name] for name in ('LEAF_BASE', 'LEAF_READY', 'LEAF_HITS',
            'LEAF_MISSES', 'LEAF_STORES', 'POINT_READY', 'POINT_HITS', 'POINT_MISSES',
            'TEXT_STORE_SLOT')], list(range(712, 784, 8)))
        for maximum in (0, 1, 128, native.MAXIMUM):
            baseline = native.buffer_sizes(maximum)[1]
            old = native.buffer_sizes(maximum, key_cache=True)[1]
            current = native.buffer_sizes(maximum, key_cache=True, leaf_cache=True)[1]
            self.assertEqual(old - baseline, 163840)
            self.assertEqual(current - old, 311296)
            key = current - 8192 - 311296 - 163840
            leaf = current - 8192 - 311296
            self.assertEqual(key, baseline - 8192)
            self.assertEqual(key + 163840, leaf)
            self.assertEqual(leaf + 1024 * 304, current - 8192)
        self.assertEqual(48 + 64 * 4, 304)

    def test_02_core_summary_hits_misses_and_legacy_headers(self):
        handle, base = 7, 1024
        slot = base + handle * 304
        for magic in (native.MAGIC, native.CACHED_MAGIC, native.KEY_SUMMARY_MAGIC, native.LEAF_MAGIC):
            for variant in ('valid', 'absent', 'collision', 'container'):
                workspace = bytearray(4096)
                _put(workspace, [(0, magic), (16, 11), (24, 29), (712, base), (720, 13),
                    (728, 17), (736, 19), (slot, handle), (slot + 8, 2), (slot + 16, 3),
                    (200, 23), (208, 29), (216, 31), (224, 37)])
                if variant == 'absent': _put(workspace, [(slot, 0)])
                if variant == 'collision': _put(workspace, [(slot, handle + 1024)])
                if variant == 'container': _put(workspace, [(slot + 8, native.LIST)])
                hit = magic == native.LEAF_MAGIC and variant == 'valid'
                expected = bytearray(workspace)
                if magic == native.LEAF_MAGIC:
                    _put(expected, [(720, slot if hit else 0), (728 if hit else 736, 18 if hit else 20)])
                if hit:
                    _put(expected, [(24, 101)])
                else:
                    _put(expected, [(8, native.SUMMARY), (16, 12), (24, 101),
                        (200, handle), (208, 0), (216, 0), (224, 0)])
                status, actual = self.invoke('leaf_summary', workspace, [handle, 101])
                self.assertEqual(status, 0 if hit else 1)
                self.assertEqual(actual, expected)

    def test_03_core_facts_and_scalar_publication_are_exact(self):
        source = struct.pack('<7Q', native.LEAF_MAGIC, 11, native.CHILD, 9, 13, 17, 19)
        slot = 2048
        for ready in (0, slot):
            workspace = bytearray(4096)
            _put(workspace, [(0, native.LEAF_MAGIC), (720, ready),
                (slot, 5), (slot + 8, 2), (slot + 16, 127), (slot + 24, 1), (slot + 32, 0)])
            facts = (2, 127, 1, 0) if ready else (9, 13, 17, 19)
            for offset, value in zip((24, 32, 40, 48), facts):
                result, after = self.invoke('leaf_fact', workspace, [offset], b'' if ready else source)
                self.assertEqual(result, value)
                self.assertEqual(after, workspace)
            expected = bytearray(workspace)
            _put(expected, [(328, 5), (336, facts[0]), (344, facts[1]), (352, facts[2]),
                (360, facts[3]), (368, 2), (376, 512), (384, 108),
                (392, 0), (424, 0), (24, 20)])
            status, actual = self.invoke('leaf_norm_begin', workspace, [5, 2, 512, 108],
                                         b'' if ready else source)
            self.assertEqual((status, actual), (0, expected))
        for kind in range(6):
            workspace = bytearray(4096)
            base, handle = 1024, 3
            target = base + handle * 304
            _put(workspace, [(0, native.LEAF_MAGIC), (712, base), (744, 11)])
            expected = bytearray(workspace)
            if kind <= 3:
                _put(expected, [(target + 8, kind), (target + 16, 13),
                    (target + 24, 17), (target + 32, 19), (target + 40, 0),
                    (target, handle), (744, 12)])
            status, actual = self.invoke('leaf_save_scalar', workspace, [handle, kind, 13, 17, 19])
            self.assertEqual((status, actual), (0, expected))
            if kind <= 3:
                status, after = self.invoke('leaf_save_scalar', actual, [handle + 1024, kind, 23, 29, 31])
                self.assertEqual((status, after), (0, actual))

    def test_04_core_string_candidates_publish_after_full_admission(self):
        for points, maximum, expected_status in [
                ((65, 10, 0x1f9ea), 64, 0), ((), 2, 0),
                ((65,) * 65, 128, 0), ((65, 0xd800), 64, 115),
                ((65, 0x1f9ea), 4, 108)]:
            workspace = bytearray(4096)
            base, handle = 1024, 2
            slot = base + handle * 304
            _put(workspace, [(0, native.LEAF_MAGIC), (32, maximum), (48, 0), (712, base)])
            status, workspace = self.invoke('text_begin', workspace, [handle, len(points), 0, 0, 1])
            self.assertEqual(status, 0)
            self.assertEqual(_u64(workspace, 776), slot)
            self.assertEqual(_u64(workspace, slot), 0)
            packet = struct.pack('<7Q', native.LEAF_MAGIC, 1, native.POINTS, len(points), 0, 0, 0)
            packet += struct.pack('<' + 'I' * len(points), *points)
            if points:
                status, workspace, output = self.text_step(workspace, packet, 31)
                self.assertEqual(status, expected_status)
                self.assertEqual(output, b'\0' * 512)
                self.assertEqual(_u64(workspace, slot), 0)
                self.assertEqual(_u64(workspace, slot + 40), 0)
                if status:
                    continue
            status, workspace, output = self.text_step(workspace, b'', 30)
            self.assertEqual(status, 0)
            self.assertEqual(struct.unpack_from('<6Q', workspace, slot),
                             (handle, 4, len(points), 0, 0, int(len(points) <= 64)))
            self.assertEqual(_u64(workspace, 24), 1)
            if len(points) <= 64:
                self.assertEqual(bytes(workspace[slot + 48:slot + 48 + len(points) * 4]),
                                 struct.pack('<' + 'I' * len(points), *points))
            else:
                self.assertEqual(bytes(workspace[slot + 48:slot + 304]), b'\0' * 256)

    def test_05_core_packet_extent_and_three_span_canaries(self):
        _packet_boundaries(self, key_tests._CoreImage(self.program))

    def test_06_core_small_complete_protocol_projection(self):
        image = key_tests._CoreImage(self.program)
        text = 'x'
        graph = [text, text, None, None]
        old = _capture(image, graph, 128, protocol=4)
        current = _capture(image, graph, 128, protocol=5)
        self.assertEqual(old['outcome'], ('ok', b'["x","x",null,null]'))
        omitted = _projection(self, old, current)
        self.assertTrue(any(row['request'][0] == native.SUMMARY for row in omitted))
        self.assertTrue(any(row['request'][0] == native.POINTS for row in omitted))
        self.assertGreater(image.calls, 0)

    def test_07_bridge_capability_and_fresh_zeroed_sessions(self):
        image = object()
        sessions = [_session(image, 'x', 128, protocol=p) for p in (2, 3, 4, 5, 5)]
        self.assertEqual([s._protocol_magic for s in sessions],
            [native.MAGIC, native.CACHED_MAGIC, native.KEY_SUMMARY_MAGIC, native.LEAF_MAGIC, native.LEAF_MAGIC])
        for session in sessions:
            self.assertEqual(bytes(session.workspace), b'\0' * len(session.workspace))
        self.assertIsNot(sessions[-1].observer, sessions[-2].observer)
        self.assertIsNot(sessions[-1].workspace, sessions[-2].workspace)
        _put(sessions[-1].workspace, [(728, 1)])
        self.assertEqual(_u64(sessions[-2].workspace, 728), 0)
        class Custom(native.ForeignGraphObserver):
            pass
        for observer, renderer in ((Custom(), None), (native.ForeignGraphObserver(), lambda x: '0')):
            session = _session(image, 1, observer=observer, renderer=renderer)
            self.assertEqual(session._protocol_magic, native.MAGIC)
            self.assertFalse(session.leaf_cache)
        observer = native.ForeignGraphObserver()
        observer.points = lambda *args: ()
        self.assertEqual(_session(image, 'x', observer=observer)._protocol_magic, native.MAGIC)
        original = native.ForeignGraphObserver.summary
        with patch.object(native.ForeignGraphObserver, 'summary', lambda self, h: original(self, h)):
            self.assertEqual(_session(image, 1)._protocol_magic, native.MAGIC)
        with patch.object(sys, 'get_int_max_str_digits', lambda: 0):
            self.assertEqual(_session(image, 1)._protocol_magic, native.MAGIC)

    def test_08_core_repeated_leaf_keeps_depth_queue_and_node_admission(self):
        workspace = bytearray(8192)
        slot = 4096 + 304
        _put(workspace, [(0, native.LEAF_MAGIC), (40, 1), (88, 2), (96, 2),
            (232, 1024), (712, 4096), (slot, 1), (slot + 8, 0),
            (1024, 1), (1032, 0), (1040, 0), (1048, 1), (1056, 0), (1064, 0)])
        status, first = self.invoke('preflight', workspace, [1], b'')
        self.assertEqual((status, _u64(first, 80), _u64(first, 88), _u64(first, 728)), (0, 1, 1, 1))
        status, first = self.invoke('preflight', first, [2], b'')
        self.assertEqual(status, 0)
        status, second = self.invoke('preflight', first, [1], b'')
        self.assertEqual((status, _u64(second, 80), _u64(second, 88), _u64(second, 728)), (102, 2, 0, 1))
        for depth, queued, expected in ((129, 1, 101), (0, 0, 199)):
            fresh = bytearray(workspace)
            _put(fresh, [(40, 3), (88, queued), (96, 1), (1032, depth)])
            status, after = self.invoke('preflight', fresh, [1], b'')
            self.assertEqual(status, expected)
            self.assertEqual(_u64(after, 80), 0)
            self.assertEqual(_u64(after, 728), 0)


class WireLeafCacheNativeTests(unittest.TestCase):
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
        old = _capture(self.image, value, maximum, protocol=4, **options)
        current = _capture(self.image, value, maximum, protocol=5, **options)
        self.assertEqual(old['outcome'], expected)
        omitted = _projection(self, old, current)
        return old, current, omitted

    def test_01_scalar_and_string_boundaries_full_request_projection(self):
        values = [None, False, True, 0, -1, 2 ** 127, -(2 ** 127), -0.0, 1.5, 5e-324]
        values += ['x' * n for n in (0, 1, 32, 33, 64, 65)]
        values += ['雪🧪\x7f\n\x00"\\', '\\' * 64]
        for ascii_flag in (False, True):
            for sort_flag in (False, True):
                for value in values:
                    with self.subTest(type=type(value).__name__, ascii=ascii_flag, sort=sort_flag):
                        self.compare([value, value], ensure_ascii=ascii_flag, sort_keys=sort_flag)

    def test_02_fanout_depth_cycle_budget_and_failure_order(self):
        cycle = []
        cycle.append(cycle)
        nested = None
        for _ in range(129):
            nested = [nested]
        shared = ['same']
        values = [[shared] * 6, ['same'] * 16, cycle, nested,
                  ['\ud800', 'same'], ['same', '\ud800'], [object(), '\ud800'],
                  ['\ud800', object()], {1: 0, '1': 1}, {None: 0, 'null': 1},
                  [float('nan'), '\ud800'], [float('inf'), 'same'],
                  ['x' * 256, '\ud800'], ['\ud800', 'x' * 256]]
        for value in values:
            for maximum in (0, 1, 2, 16, 128, 4096):
                with self.subTest(type=type(value).__name__, maximum=maximum):
                    self.compare(value, maximum, ensure_ascii=False, sort_keys=True)

    def test_03_capacity_and_handle_collisions_fall_back(self):
        values = [2 ** 40 + index for index in range(1025)]
        graph = values + values
        results = []
        for protocol in (4, 5):
            observer = native.ForeignGraphObserver()
            for index, value in enumerate(values, 1):
                self.assertEqual(observer.register(value), index)
            results.append(_capture(self.image, graph, 230000, protocol=protocol, observer=observer))
        expected = base_tests.outcome(lambda: program_tools._reference_bounded_json_wire(
            graph, 230000, ensure_ascii=False, sort_keys=True))
        self.assertEqual(results[0]['outcome'], expected)
        omitted = _projection(self, *results)
        self.assertGreater(len(omitted), 0)
        self.assertEqual(len(results[1]['leaves']), 1024)
        self.assertIn(1025, results[1]['leaves'])
        self.assertNotIn(1, results[1]['leaves'])
        # Reverse DFS admits handle1025 first; its colliding handle1 remains
        # an original SUMMARY observation on every later use.
        self.assertTrue(any(r['request'][0] == native.SUMMARY and r['request'][2] == 1
                            for r in results[1]['trace']))

    def test_04_protocol_packets_extents_and_canaries(self):
        _packet_boundaries(self, self.image)
        for maximum in (0, 1, 2, 16, 128):
            session = _session(self.image, ['same', 'same'], maximum)
            output = ctypes.create_string_buffer(maximum + 32)
            work = ctypes.create_string_buffer(len(session.workspace) + 32)
            ctypes.memset(output, 0xa5, len(output))
            ctypes.memset(work, 0xa5, len(work))
            size = len(session.workspace)
            session.output = ctypes.cast(ctypes.byref(output, 16), ctypes.POINTER(ctypes.c_char))
            session.workspace = (ctypes.c_char * size).from_buffer(work, 16)
            ctypes.memset(session.workspace, 0, size)
            base_tests.outcome(session.run)
            self.assertEqual(output.raw[:16] + output.raw[-16:], b'\xa5' * 32)
            self.assertEqual(work.raw[:16] + work.raw[-16:], b'\xa5' * 32)

    def test_05_custom_replaced_observer_and_renderer_stay_protocol02(self):
        class Custom(native.ForeignGraphObserver):
            pass
        graph = [{'b': 1.5, 'a': 2}] * 3
        original = native.ForeignGraphObserver.summary
        for mode in ('subclass', 'instance', 'class', 'digit_limit', 'renderer'):
            results, calls = [], []
            def render(number):
                calls.append(number)
                return '1.5'
            for protocol in (2, 5):
                observer = Custom() if mode == 'subclass' else native.ForeignGraphObserver()
                if mode == 'instance':
                    observer.summary = lambda h, observer=observer: original(observer, h)
                with patch.object(native.ForeignGraphObserver, 'summary',
                        (lambda self, h: original(self, h)) if mode == 'class' else original), \
                        patch.object(sys, 'get_int_max_str_digits',
                        (lambda: 0) if mode == 'digit_limit' else sys.get_int_max_str_digits):
                    result = _capture(self.image, graph, 4096, protocol=protocol, observer=observer,
                                      renderer=render if mode == 'renderer' else None)
                self.assertFalse(result['session'].leaf_cache)
                self.assertEqual(result['session']._protocol_magic, native.MAGIC)
                results.append((result['outcome'], result['trace'], bytes(result['session'].workspace)))
            self.assertEqual(results[0], results[1])
            if mode == 'renderer':
                self.assertEqual(calls, [1.5] * 6)
                self.assertGreater(sum(r['request'][0] == native.FORMAT_FLOAT for r in results[0][1]), 0)

    def test_06_ordinary_fresh_sessions_forbid_host_encoder_and_retained_owner(self):
        value = [{'b': 'same', 'a': 2}] * 3
        expected = program_tools._reference_bounded_json_wire(value, 4096, ensure_ascii=False)
        seen = []
        original_run = native.WireSession.run
        def run(session):
            self.assertEqual(bytes(session.workspace), b'\0' * len(session.workspace))
            seen.append(session)
            return original_run(session)
        with patch.object(native.WireSession, 'run', run), \
                patch.object(program_tools, '_reference_bounded_json_wire', side_effect=AssertionError('retained owner')), \
                patch.object(json.JSONEncoder, 'iterencode', side_effect=AssertionError('host encoder')):
            for _ in range(2):
                self.assertEqual(self.image.encode_ordinary(value, 4096, ensure_ascii=False), expected)
        self.assertEqual(len(seen), 2)
        self.assertIsNot(seen[0].observer, seen[1].observer)
        self.assertIsNot(seen[0].workspace, seen[1].workspace)
        for session in seen:
            self.assertTrue(session.leaf_cache)
            self.assertEqual(session._protocol_magic, native.LEAF_MAGIC)
            self.assertGreater(_u64(session.workspace, 728), 0)
            self.assertGreater(_u64(session.workspace, 760), 0)

    def test_07_long_strings_and_key_value_identity_keep_original_windows(self):
        for length in (0, 1, 32, 33, 64, 65, 1025):
            text = 'x' * length
            graph = [{text: text}, {text: text}, text]
            for ascii_flag in (False, True):
                old, current, omitted = self.compare(graph, 16384, ensure_ascii=ascii_flag, sort_keys=True)
                if length > 64:
                    self.assertFalse(any(r['request'][0] == native.POINTS for r in omitted))
                    self.assertTrue(any(r['request'][0] == native.POINTS and r['text_mode'] == 3
                                        for r in current['trace']))
                self.assertEqual(old['key_rows'], current['key_rows'])

    def test_08_digit_limit_and_limb_requests_are_never_cached(self):
        original = sys.get_int_max_str_digits()
        try:
            giant = 10 ** 700
            for limit in (0, 640):
                sys.set_int_max_str_digits(limit)
                for value in ([giant, giant], [7, 7], [giant, '\ud800'], ['\ud800', giant]):
                    old, current, omitted = self.compare(value, 4096, ensure_ascii=False, sort_keys=True)
                    self.assertTrue(all(r['request'][0] in (native.SUMMARY, native.POINTS) for r in omitted))
                    if value == [7, 7]:
                        self.assertEqual(sum(r['request'][0] == native.DIGIT_LIMIT for r in current['trace']), 2)
                        self.assertEqual(sum(r['request'][0] == native.LIMBS for r in current['trace']), 2)
        finally:
            sys.set_int_max_str_digits(original)
