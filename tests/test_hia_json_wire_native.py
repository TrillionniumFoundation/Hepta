"""Independent old-wire comparisons and native continuation boundary controls."""
from __future__ import annotations

import ast
import ctypes
import gc
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import weakref
import zipfile

from hepta.hia_json_wire_native import (
    SOURCE, SCHEMA, MAGIC, MAXIMUM, ForeignGraphObserver, NativeJsonWire, WireSession,
    installed_json_wire, SUMMARY, CHILD, POINTS, LIMBS, DIGIT_LIMIT, FORMAT_FLOAT,
)
from hepta.hia_program_tools import bounded_json_wire, HIAEditRejected

ROOT = Path(__file__).resolve().parents[1]
COLD = 'HEPTA_HIA_JSON_WIRE_COLD_REPORT'
DEVELOPMENT = 'HEPTA_HIA_JSON_WIRE_DEVELOPMENT_MANIFEST'
FIXTURE_EVIDENCE = 'HEPTA_HIA_JSON_WIRE_FIXTURE_EVIDENCE'


def outcome(operation):
    try:
        return 'ok', operation()
    except Exception as exc:
        return type(exc).__name__, str(exc)


class WireSourceTests(unittest.TestCase):
    def test_generated_source_and_lazy_exact_type_observer(self):
        from tools.generate_hia_json_wire import document
        from hepta.hia_agent_assembly import render_assembly
        self.assertEqual(SOURCE.read_text(), render_assembly(document()))
        class Hook(list):
            def __len__(self):
                raise AssertionError('foreign subtype hook entered')
            def __iter__(self):
                raise AssertionError('foreign subtype hook entered')
        observer = ForeignGraphObserver()
        root = observer.register([Hook(), [1, 2]])
        self.assertEqual(len(observer._objects), 1)
        self.assertEqual(observer.summary(root), (5, 2, 0, 0))
        self.assertEqual(len(observer._objects), 1)
        child = observer.child(root, 0, 0)
        self.assertEqual(observer.summary(child), (8, 0, 0, 0))
        self.assertEqual(observer.register(observer.value(child)), child)
        text = observer.register('雪\ud800🧪')
        self.assertEqual(observer.points(text, 0, 3), (38634, 55296, 129514))
        with self.assertRaises(IndexError):
            observer.points(text, 2, 2)
        reads = []
        class TextSubtype(str):
            def __getitem__(self, index):
                reads.append(index)
                return super().__getitem__(index)
        text = observer.register(TextSubtype('abc'))
        self.assertEqual(observer.points(text, 1, 2), (98, 99))
        self.assertEqual(reads, [1, 2])

    def test_word_helpers_preserve_bounds_and_partial_byte_stores(self):
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import HIAProgramTrap, _Machine, _Owner, _View
        from tools.generate_hia_json_wire import source_program
        program = assemble_program(SOURCE.read_bytes())
        names = {node.name: 'f' + str(index)
                 for index, node in enumerate(ast.parse(source_program()).body)}
        functions = {fn['name']: fn for fn in program.as_dict()['functions']}
        for name, width in (('read64', 8), ('read32', 4), ('get', 8),
                            ('put', 8), ('get32', 4), ('put32', 4)):
            writing = name.startswith('put')
            for length in (0, 1, 3, 4, 7, 8, 9, 16):
                before = bytes((index * 31 + 9) & 255 for index in range(length))
                offsets = {0, 1, max(0, length - width), max(0, length - width + 1),
                           length, length + 1, (1 << 64) - 1}
                for offset in sorted(offsets):
                    with self.subTest(helper=name, length=length, offset=offset):
                        owner = _Owner(-1, bytearray(before))
                        arguments = [_View(owner, not name.startswith('read')), offset]
                        value = 0x8877665544332211
                        if writing:
                            arguments.append(value)
                        machine = _Machine(program, 100000, 64 << 20, None, 128)
                        complete = offset <= length and width <= length - offset
                        if complete:
                            result = machine.invoke(functions[names[name]], arguments)
                            expected = 0 if writing else int.from_bytes(before[offset:offset + width], 'little')
                            self.assertEqual(result, [expected])
                        else:
                            with self.assertRaises(HIAProgramTrap) as caught:
                                machine.invoke(functions[names[name]], arguments)
                            self.assertEqual(caught.exception.code, 'bounds')
                        expected_bytes = bytearray(before)
                        if writing and offset < length:
                            available = min(width, length - offset)
                            expected_bytes[offset:offset + available] = value.to_bytes(8, 'little')[:available]
                        self.assertEqual(owner.data, expected_bytes)

    def test_inlined_field_stores_keep_evaluation_and_partial_write_order(self):
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import HIAProgramTrap, _Machine, _Owner, _View
        from tools.generate_hia_json_wire import source_program
        program = assemble_program(SOURCE.read_bytes())
        names = {node.name: 'f' + str(index)
                 for index, node in enumerate(ast.parse(source_program()).body)}
        functions = {fn['name']: fn for fn in program.as_dict()['functions']}
        mask = (1 << 64) - 1

        def read(data, offset):
            if offset > len(data) or len(data) - offset < 8:
                raise IndexError
            return int.from_bytes(data[offset:offset + 8], 'little')

        def write(data, offset, value):
            for index, byte in enumerate((value & mask).to_bytes(8, 'little')):
                data[offset + index] = byte

        def check(name, initial, output, scalars, operation):
            expected, expected_output = bytearray(initial), bytearray(output)
            try:
                returned = operation(expected, expected_output)
                trapped = False
            except (IndexError, OverflowError):
                trapped = True
            owner, out = _Owner(-1, bytearray(initial)), _Owner(-2, bytearray(output))
            args = ([_View(out, True), _View(owner, True)] if name == 'emit'
                    else [_View(owner, True)]) + scalars
            machine = _Machine(program, 100000, 64 << 20, None, 128)
            if trapped:
                with self.assertRaises(HIAProgramTrap) as caught:
                    machine.invoke(functions[names[name]], args)
                self.assertEqual(caught.exception.code, 'bounds')
            else:
                self.assertEqual(machine.invoke(functions[names[name]], args), [returned])
            self.assertEqual(owner.data, expected)
            self.assertEqual(out.data, expected_output)

        for length in (0, 15, 16, 23, 24, 25, 31, 32, 199, 200, 207,
                       208, 215, 216, 223, 224, 231, 232, 512):
            def request(data, output):
                sequence = (read(data, 16) + 1) & mask
                for offset, value in ((16, sequence), (8, 7), (200, 11),
                                      (208, 13), (216, 17), (224, 19), (24, 31)):
                    write(data, offset, value)
                return 1
            with self.subTest(helper='ask', length=length):
                check('ask', b'\xff' * length, b'', [7, 11, 13, 17, 19, 31], request)

        for name, lengths in (('text_byte', (0, 39, 40, 471, 472, 479, 480, 487, 488, 512)),
                              ('emit', (0, 39, 40, 111, 112, 119, 120, 512))):
            for length in lengths:
                for count in (0, 2, mask):
                    for target in (0, max(0, length - 1), length, mask):
                        initial = bytearray(b'\xa5' * length)
                        for offset, value in ((32, 2), (112 if name == 'emit' else 472, count),
                                              (480, target)):
                            if offset + 8 <= length:
                                write(initial, offset, value)
                        def append(data, output):
                            offset = 112 if name == 'emit' else 472
                            current = read(data, offset)
                            if current < read(data, 32):
                                if name == 'emit':
                                    output[current] = 0x7f
                                else:
                                    data[(read(data, 480) + current) & mask] = 0x7f
                            write(data, offset, current + 1)
                            return 0
                        with self.subTest(helper=name, length=length, count=count, target=target):
                            check(name, initial, b'\x5a', [0x7f], append)

    def test_independent_core_vm_drives_foreign_observations(self):
        # The same authoring is executed by the independent Core interpreter;
        # no flat native executable or native compiler participates.
        script = r'''
import ctypes,json,resource
resource.setrlimit(resource.RLIMIT_AS,(384 << 20,384 << 20))
from hepta.hia_agent_assembly import assemble_program
from hepta.hia_program_runtime import _Machine,_Owner,_View
from hepta.hia_json_wire_native import SOURCE,NativeJsonWire
program=assemble_program(SOURCE.read_bytes())
class VM(NativeJsonWire):
 def __init__(self): self.calls=0
 def _entry(self,s,ns,o,no,w,nw):
  owners=[_Owner(-1,bytearray(ctypes.string_at(s,ns))),_Owner(-2,bytearray(ctypes.string_at(o,no))),_Owner(-3,bytearray(ctypes.string_at(w,nw)))]
  machine=_Machine(program,10000000,64 << 20,None,128)
  result=machine.invoke(program.as_dict()['functions'][0],[_View(owners[0],False),_View(owners[1],True),_View(owners[2],True)])[0]
  ctypes.memmove(o,bytes(owners[1].data),no);ctypes.memmove(w,bytes(owners[2].data),nw)
  self.calls+=1
  return result
image=VM()
wire=image.encode({'z':[True], 'a':'雪'},128,ensure_ascii=False)
assert wire==b'{"a":"\xe9\x9b\xaa","z":[true]}',wire
print(json.dumps({'native_image_loaded':False,'calls':image.calls,'wire_hex':wire.hex()}))
'''
        result = subprocess.run([sys.executable, '-B', '-c', script], cwd=ROOT,
                                capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        receipt = json.loads(result.stdout)
        self.assertFalse(receipt['native_image_loaded'])
        self.assertGreater(receipt['calls'], 10)


class WireNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cold, development = os.environ.get(COLD), os.environ.get(DEVELOPMENT)
        if cold and development:
            raise AssertionError('development image cannot override current cold evidence')
        if not cold and not development:
            raise unittest.SkipTest('requires explicit JSON wire cold report or development manifest')
        cls.temp = None
        evidence = os.environ.get(FIXTURE_EVIDENCE)
        if evidence:
            cls.folder = Path(evidence).absolute()
            cls.folder.mkdir(mode=0o700, parents=True)
        else:
            cls.temp = tempfile.TemporaryDirectory(prefix='hia-json-wire-tests-')
            cls.folder = Path(cls.temp.name)
            cls.addClassCleanup(cls.temp.cleanup)
        if cold:
            from tools.build_hia_json_wire import build
            report = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(report['nested_report']).read_bytes())
            cls.compiler = Path(nested['generations'][-1]['produced_image'])
            cls.manifest = build(cls.folder / 'build', cls.compiler, Path(cold))
            cls.scope = 'MATCHING_SOURCE_COLD_BUILD'
        elif development:
            cls.manifest = Path(development).resolve(strict=True)
            request = json.loads((cls.manifest.parent / 'json-wire.request.json').read_bytes())
            cls.compiler = Path(request['image'])
            if sha256(cls.compiler.read_bytes()).hexdigest() != json.loads(cls.manifest.read_bytes())['compiler_sha256']:
                raise AssertionError('development compiler receipt changed')
            cls.scope = 'EXPLICIT_DEVELOPMENT_ONLY'
        cls.image = installed_json_wire(str(cls.manifest))
        # Reuse an explicitly admitted current-source cold builder when cold is
        # selected; a development compiler reuse stays visibly development.
        if cold:
            from tools.build_hia_agent_binary64_format import build
            format_manifest = build(cls.folder / 'format', cls.compiler, Path(cold))
        else:
            from tools.qualify_hia_selfhost import compile_stage
            directory = cls.folder / 'format'
            directory.mkdir()
            source = ROOT / 'examples/hia_bootstrap/agent_binary64_format.hepta'
            image, receipt = compile_stage(directory, 'agent-binary64-format', cls.compiler, source.read_bytes())
            format_manifest = directory / 'manifest.json'
            format_manifest.write_text(json.dumps({'schema': 'hepta.hia.agent-binary64-format-native.v1',
                'source_sha256': sha256(source.read_bytes()).hexdigest(), 'image_path': image.name,
                'image_sha256': sha256(image.read_bytes()).hexdigest(),
                'compiler_sha256': sha256(cls.compiler.read_bytes()).hexdigest()}))
        from hepta.hia_agent_binary64_format_native import installed_agent_binary64_format
        cls.format_image = installed_agent_binary64_format(str(format_manifest))

    @classmethod
    def tearDownClass(cls):
        if cls.temp is not None:
            cls.temp.cleanup()

    def assert_same(self, value, maximum=4096, *, ensure_ascii=False, sort_keys=True, renderer=False):
        callback = (lambda number: self.format_image.render(number).decode('ascii')) if renderer else None
        expected = outcome(lambda: bounded_json_wire(value, maximum, ensure_ascii=ensure_ascii,
                            sort_keys=sort_keys, float_renderer=callback))
        with (patch('hepta.hia_program_tools.bounded_json_wire', side_effect=AssertionError('retained owner')),
              patch('json.JSONEncoder.iterencode', side_effect=AssertionError('host encoder'))):
            actual = outcome(lambda: self.image.encode(value, maximum, ensure_ascii=ensure_ascii,
                             sort_keys=sort_keys, float_renderer=callback))
        self.assertEqual(actual, expected)
        return actual

    def test_scalar_bytes_utf8_escaping_binary64_and_tuple_order(self):
        values = [None, True, False, 0, -1, 10 ** 100, -10 ** 100, -0.0, 1.0, 1.25,
                  1e15, 1e16, 1e-4, 1e-5, 1e-300, 5e-324, 1.7976931348623157e308,
                  '', '雪🧪\x7f\n\x00"\\', [], (), {}, (1, 'x', [False]),
                  {'z': {'b': 2, 'a': 1}, 'a': [1, 2, 3]}]
        for ensure_ascii in (False, True):
            for sort_keys in (False, True):
                for value in values:
                    with self.subTest(value=value, ascii=ensure_ascii, sort=sort_keys):
                        self.assert_same(value, ensure_ascii=ensure_ascii, sort_keys=sort_keys)
        rng = random.Random(80417)
        for _ in range(384):
            bits = rng.getrandbits(64)
            value, = struct.unpack('<d', struct.pack('<Q', bits))
            if math.isfinite(value):
                self.assert_same(value)

    def test_reverse_dfs_key_first_queued_cycles_and_depth_refusals(self):
        cycle = []
        cycle.append(cycle)
        cases = [(cycle, 1), (cycle, 2), (cycle, 3),
                 ([object(), '\ud800'], 100), (['\ud800', object()], 100),
                 ({'a': '\ud800', float('nan'): object()}, 100),
                 ({'a': object(), 'b': '\ud800'}, 100),
                 ([[None] * 4, [None] * 4], 6),
                 ({('not', 'a', 'JSON', 'key'): '\ud800'}, 100),
                 ({1: 0, '1': '\ud800'}, 100),
                 ({None: 0, 'null': 1}, 100), ({True: 0, 'true': 1}, 100),
                 ({1.25: 0, '1.25': 1}, 100), ({float('inf'): 0}, 100)]
        shared = ['a']
        cases.append(([shared, shared], 100))
        nested = 0
        for _ in range(129):
            nested = [nested]
        cases.append((nested, 4096))
        for value, maximum in cases:
            self.assert_same(value, maximum)
        class Huge:
            def summary(self, handle): return 5, (1 << 63), 0, 0
            def child(self, *args): raise AssertionError('fanout must be rejected before children')
        self.assertEqual(outcome(lambda: self.image.encode_observed(Huge(), 1, 4096)),
                         ('HIAEditRejected', 'E_HIA_EDIT: JSON container exceeds queued-node/byte budget'))

    def test_numeric_key_sorting_and_unicode_lexicographic_order(self):
        numeric = [-(10 ** 100), -1e40, -2 ** 53 - 1, -1.5, -1, -5e-324,
                   0, 5e-324, 0.5, 1, 1.5, 2 ** 53 + 1, 1e40, 10 ** 100]
        values = [{key: index for index, key in enumerate(reversed(numeric))},
                  {'雪': 1, '🧪': 2, '\ue000': 3, 'a': 4, 'a\n': 5, 'a\x00': 6},
                  {None: 1}, {None: 1, 'z': 2}, {'x': 1, 3: 4}, {False: 1, 1.5: 2}]
        for value in values:
            for sort in (True, False):
                self.assert_same(value, sort_keys=sort)
        rng = random.Random(9016)
        for _ in range(64):
            keys = [rng.randrange(-1 << 90, 1 << 90), rng.uniform(-1e20, 1e20),
                    math.ldexp(rng.random(), rng.randrange(-1000, 1000)), rng.randrange(-10, 10)]
            self.assert_same(dict.fromkeys(keys, None))

    def test_integer_magnitude_digit_limit_order_and_late_numeric_failures(self):
        original = sys.get_int_max_str_digits()
        try:
            sys.set_int_max_str_digits(640)
            giant = 10 ** 700
            for value in [giant, -giant, [giant, '\ud800'], ['\ud800', giant],
                          {giant: '\ud800'}, {'x': giant}, {10 ** 639: 1}]:
                self.assert_same(value, 4096)
            sys.set_int_max_str_digits(0)
            for value in [giant, -giant, {giant: 1}, 2 ** 8192 - 1]:
                self.assert_same(value, 4096)
        finally:
            sys.set_int_max_str_digits(original)
        for renderer in (False, True):
            for value in [float('nan'), float('inf'), ['x' * 20, float('nan')],
                          {'x': 'a' * 20, 'z': float('nan')}, [float('nan'), '\ud800']]:
                for maximum in (4, 24, 25, 26, 32, 128):
                    self.assert_same(value, maximum, renderer=renderer)

    def test_fragment_boundaries_individual_strings_and_full_eight_MiB_extent(self):
        for value in [['a', 'b', 'c'], {'a': 'b', 'c': 'd'}, [['a'], 'b'], [[], {}],
                      ['\x00' * 4, '\ud800'], ['\ud800', '\x00' * 4], {'\x00' * 4: 0}]:
            for maximum in range(40):
                self.assert_same(value, maximum)
        self.assert_same('a' * (MAXIMUM - 2), MAXIMUM)
        # Each string passes its own preflight. A later invalid string must win
        # before total encoded size is examined; no aggregate transport cap.
        self.assert_same(['\ud800', 'a' * (MAXIMUM - 2)], MAXIMUM)
        self.assert_same(['a' * (MAXIMUM // 2), 'b' * (MAXIMUM // 2)], MAXIMUM)

    def test_actual_formatter_seam_is_lazy_and_observes_key_then_value_order(self):
        value = {1.25: [2.5, 3.5], 4.5: 5.5}
        observed = []
        def render(number):
            observed.append(struct.pack('<d', number).hex())
            return self.format_image.render(number).decode('ascii')
        expected = bounded_json_wire(value, 4096, ensure_ascii=False, float_renderer=render)
        expected_trace = observed[:]
        observed.clear()
        self.assertEqual(self.image.encode(value, 4096, float_renderer=render), expected)
        self.assertEqual(observed, expected_trace)
        observed.clear()
        result = outcome(lambda: self.image.encode([1.25, '\ud800'], 4096, float_renderer=render))
        self.assertEqual(result[0], 'HIAEditRejected')
        self.assertEqual(observed, [])

    def test_random_independent_graphs_all_budget_profiles(self):
        rng = random.Random(470912)
        leaves = [None, True, False, 0, 1, -1, 10 ** 100, -10 ** 100, 1.25, -0.0,
                  1e200, 5e-324, float('nan'), float('inf'), '', 'a', '雪', '🧪', '\ud800', '\n', '\x7f', object()]
        def graph(depth):
            if depth == 0 or rng.randrange(3) == 0:
                return rng.choice(leaves)
            if rng.randrange(2) == 0:
                return [graph(depth - 1) for _ in range(rng.randrange(5))]
            keys = rng.sample(['a', 'b', 'z', 0, 1, -1, 1.5, False, None, '1', 'null', 'true'], rng.randrange(5))
            return {key: graph(depth - 1) for key in keys}
        for index in range(1200):
            with self.subTest(index=index):
                self.assert_same(graph(3), rng.choice([0, 1, 2, 3, 4, 5, 8, 16, 32, 128, 4096]),
                                 ensure_ascii=bool(rng.randrange(2)), sort_keys=bool(rng.randrange(2)))

    def test_protocol_sequence_extent_and_output_canaries(self):
        observer = ForeignGraphObserver()
        root = observer.register({'x': [1, 2]})
        for mutation in ('sequence', 'opcode', 'short', 'long'):
            session = WireSession(self.image, observer, root, 128, ensure_ascii=False, sort_keys=True)
            self.assertEqual(session.step(), 1)
            packet = bytearray(session.observe())
            if mutation == 'sequence': struct.pack_into('<Q', packet, 8, 0)
            if mutation == 'opcode': struct.pack_into('<Q', packet, 16, CHILD)
            if mutation == 'short': packet.pop()
            if mutation == 'long': packet.append(0)
            self.assertEqual(session.step(bytes(packet)), 199)
            with self.assertRaises(RuntimeError): session.step()
        for maximum in (0, 1, 2, 16, 128):
            observer = ForeignGraphObserver()
            root = observer.register(['a' * 10, 'b' * 10])
            session = WireSession(self.image, observer, root, maximum, ensure_ascii=False, sort_keys=True)
            raw = ctypes.create_string_buffer(maximum + 32)
            ctypes.memset(raw, 0xA5, len(raw))
            session.output = ctypes.cast(ctypes.byref(raw, 16), ctypes.POINTER(ctypes.c_char))
            while True:
                status = session.step()
                if status != 1: break
                session.observe()
            self.assertIn(status, {2, 102, 103, 108, 116})
            self.assertEqual(raw.raw[:16], b'\xa5' * 16)
            self.assertEqual(raw.raw[-16:], b'\xa5' * 16)
        for maximum in (True, None, -1, MAXIMUM + 1, 1 << 100):
            self.assert_same(None, maximum)

    def test_observations_are_once_per_request_and_never_after_terminal(self):
        class Observer(ForeignGraphObserver):
            def __init__(self, fail_once=False):
                super().__init__()
                self.calls = 0
                self.fail_once = fail_once

            def summary(self, handle):
                self.calls += 1
                if self.fail_once and self.calls == 1:
                    raise RuntimeError('intentional foreign summary failure')
                return super().summary(handle)

        def create(fail_once=False):
            observer = Observer(fail_once)
            session = WireSession(self.image, observer, observer.register(None), 32,
                                  ensure_ascii=False, sort_keys=True)
            return session, observer

        for case in ('before-request', 'repeat', 'bad-ack', 'foreign-error', 'completed'):
            with self.subTest(case=case):
                session, observer = create(case == 'foreign-error')
                if case == 'completed':
                    self.assertEqual(session.run(), b'null')
                    self.assertTrue(session.finished)
                    self.assertEqual(observer.calls, 2)  # Both HIA traversals.
                elif case != 'before-request':
                    self.assertEqual(session.step(), 1)
                    if case == 'foreign-error':
                        with self.assertRaisesRegex(RuntimeError, 'intentional foreign summary failure'):
                            session.observe()
                    else:
                        packet = bytearray(session.observe())
                        if case == 'bad-ack':
                            struct.pack_into('<Q', packet, 8, 0)
                            self.assertEqual(session.step(bytes(packet)), 199)
                            self.assertTrue(session.finished)
                    self.assertEqual(observer.calls, 1)
                before = observer.calls
                with self.assertRaises(RuntimeError):
                    session.observe()
                self.assertEqual(observer.calls, before)


    def test_private_buffer_lifetime_after_observer_exceptions_and_reentry(self):
        # The foreign callback can retain an exception traceback, and callers
        # can retain exported buffers after dropping the session. Neither
        # lifetime may trigger an early unmap or corrupt a separate session.
        for failure, expected in ((ValueError, HIAEditRejected),
                                  (RuntimeError, RuntimeError),
                                  (KeyboardInterrupt, KeyboardInterrupt),
                                  (MemoryError, MemoryError)):
            class FailingObserver(ForeignGraphObserver):
                def points(self, *args):
                    raise failure('observer failure')
            observer = FailingObserver()
            session = WireSession(self.image, observer, observer.register('outer'), MAXIMUM,
                                  ensure_ascii=False, sort_keys=True)
            output, workspace = session.output, session.workspace
            for buffer in (output, workspace):
                self.assertEqual(buffer[0], b'\0')
                self.assertEqual(buffer[-1], b'\0')
            with self.assertRaises(expected) as caught:
                session.run()
            before = (ctypes.string_at(output, 16), ctypes.string_at(workspace, 16))
            reference = weakref.ref(session)
            del session
            gc.collect()
            self.assertEqual((ctypes.string_at(output, 16), ctypes.string_at(workspace, 16)), before)
            del caught
            gc.collect()
            self.assertIsNone(reference())
            self.assertEqual(self.image.encode({'fresh': 'call'}, MAXIMUM), b'{"fresh":"call"}')
            self.assertEqual((ctypes.string_at(output, 16), ctypes.string_at(workspace, 16)), before)
            del output, workspace
            gc.collect()

        image, nested = self.image, []
        class ReentrantObserver(ForeignGraphObserver):
            entered = False
            def points(self, *args):
                if not self.entered:
                    self.entered = True
                    nested.append(image.encode({'inner': [1, '雪']}, MAXIMUM))
                return super().points(*args)
        observer = ReentrantObserver()
        root = observer.register({'z': [True, 5], 'a': 'outer'})
        self.assertEqual(image.encode_observed(observer, root, MAXIMUM),
                         b'{"a":"outer","z":[true,5]}')
        self.assertEqual(nested, [b'{"inner":[1,"\xe9\x9b\xaa"]}'])

    def test_virtual_parent_nodes_share_foreign_graph_depth_and_node_budgets(self):
        class Virtual:
            ROOT = (1 << 63) + 1
            NESTED = ROOT + 1
            def __init__(self, value):
                self.foreign = ForeignGraphObserver()
                self.value_handle = self.foreign.register(value)
                self.outer_key = self.foreign.register('outer')
                self.inner_key = self.foreign.register('value')
            def summary(self, handle):
                if handle in (self.ROOT, self.NESTED): return 7, 1, 0, 0
                return self.foreign.summary(handle)
            def child(self, handle, index, part):
                if handle == self.ROOT:
                    assert index == 0
                    return self.outer_key if part == 0 else self.NESTED
                if handle == self.NESTED:
                    assert index == 0
                    return self.inner_key if part == 0 else self.value_handle
                return self.foreign.child(handle, index, part)
            def points(self, *args): return self.foreign.points(*args)
            def limbs(self, *args): return self.foreign.limbs(*args)
        cases = [({'z': [1.25, '雪'], 'a': None}, 4096), (None, 2), (None, 3)]
        nested = 0
        for _ in range(127): nested = [nested]
        cases.append((nested, 4096))
        for value, maximum in cases:
            observer = Virtual(value)
            expected = outcome(lambda: bounded_json_wire({'outer': {'value': value}}, maximum,
                                                         ensure_ascii=False, sort_keys=True))
            actual = outcome(lambda: self.image.encode_observed(observer, observer.ROOT, maximum))
            self.assertEqual(actual, expected)

    def test_exact_full_graph_node_ceiling_and_no_early_transport_expansion(self):
        value = [None] * 262143
        expected = bounded_json_wire(value, MAXIMUM, ensure_ascii=False)
        self.assertEqual(self.image.encode(value, MAXIMUM), expected)
        observer = ForeignGraphObserver()
        root = observer.register([None] * 262144)
        with patch.object(observer, 'child', side_effect=AssertionError('pre-expanded rejected fanout')):
            result = outcome(lambda: self.image.encode_observed(observer, root, MAXIMUM))
        self.assertEqual(result, ('HIAEditRejected', 'E_HIA_EDIT: JSON container exceeds queued-node/byte budget'))

    def test_installed_wheel_resource_identity_and_no_retained_encoder(self):
        directory = Path(tempfile.mkdtemp(prefix='installed-', dir=self.folder))
        source = directory / 'source'
        source.mkdir()
        shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        for name in ('setup.py', 'pyproject.toml', 'MANIFEST.in', 'README.md'):
            shutil.copyfile(ROOT / name, source / name)
        tree = ast.parse((ROOT / 'hepta/hia_agent_contract.py').read_text())
        resources = {}
        for node in tree.body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                if node.targets[0].id in ('DISCOVERY_FILES', 'NATIVE_SOURCE_FILES', 'SOURCE_BUILD_FILES', 'COMPILER_BUILD_FILES', 'PUBLICATION_BUILD_FILES', 'BACKEND_BUILD_FILES'):
                    resources[node.targets[0].id] = ast.literal_eval(node.value)
        names = [*('docs/' + n for n in resources['DISCOVERY_FILES']), *resources['NATIVE_SOURCE_FILES'], *resources['SOURCE_BUILD_FILES'], *resources['COMPILER_BUILD_FILES'], *resources['PUBLICATION_BUILD_FILES'], *resources['BACKEND_BUILD_FILES']]
        self.assertIn('examples/hia_bootstrap/json_wire.hepta', names)
        for name in names:
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        command = [sys.executable, '-B', 'setup.py', 'bdist_wheel', '--dist-dir', str(directory / 'wheel')]
        result = subprocess.run(command, cwd=source, capture_output=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        wheel, = (directory / 'wheel').glob('*.whl')
        installed = directory / 'installed'
        with zipfile.ZipFile(wheel) as archive:
            resource = 'hepta/_data/examples/hia_bootstrap/json_wire.hepta'
            self.assertEqual(archive.read(resource), SOURCE.read_bytes())
            archive.extractall(installed)
        script = r'''
import builtins,json,pathlib,sys
from unittest.mock import patch
sys.path.insert(0,sys.argv[1])
from hepta.hia_json_wire_native import SOURCE,installed_json_wire
assert '_data' in SOURCE.parts
real_import=builtins.__import__
def no_tools(name,*args,**kwargs):
 if name=='tools' or name.startswith('tools.'):raise AssertionError('installed runtime imported tools')
 return real_import(name,*args,**kwargs)
with patch('builtins.__import__',no_tools),patch('hepta.hia_program_tools.bounded_json_wire',side_effect=AssertionError('retained')),patch('json.JSONEncoder.iterencode',side_effect=AssertionError('host encoder')):
 image=installed_json_wire(sys.argv[2]);assert image.encode({'z':1,'a':'雪'},128)==b'{"a":"\xe9\x9b\xaa","z":1}'
 original=SOURCE.read_bytes();SOURCE.write_bytes(original+b'\n')
 try:installed_json_wire(sys.argv[2])
 except ValueError as exc:assert 'source identity' in str(exc)
 else:raise AssertionError('selected source drift fell back')
 SOURCE.write_bytes(original)
print(json.dumps({'installed':True,'retained_encoder_entered':False,'source_drift_refused':True}))
'''
        result = subprocess.run([sys.executable, '-I', '-B', '-c', script, str(installed), str(self.manifest)],
                                cwd=directory, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(json.loads(result.stdout)['source_drift_refused'])
