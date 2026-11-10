"""Independent VM, fresh bootstrap and native JSON arena/consumer observations."""
from __future__ import annotations
import ctypes
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import json
from pathlib import Path
import random
import struct
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_json_decode import decode_hia_json
from hepta.hia_json_decode_native import (NativeJsonDecoder, SOURCE, SCHEMA,
    materialize, arena_sizes, installed_decoder)
from tools.generate_hia_json_decode import document

ROOT = Path(__file__).resolve().parents[1]


def vm_arena(wire, nodes=32, depth=4, *, source_path=SOURCE, sizes=None):
    from tools.hia_selfhost_bulk import Body
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import execute_program
    body = Body(0)
    output_size, workspace_size = arena_sizes(len(wire), nodes, depth) if sizes is None else sizes
    state = bytearray(workspace_size)
    struct.pack_into('<QQ', state, 48, nodes, depth)
    owners, views = [], []
    for size, initial in ((len(wire), wire), (output_size, b''), (workspace_size, state)):
        owner = body.value('buffer', 'buffer.new', [body.const('usize', size)])
        view = body.value('mutbuf', 'borrow.mut', [owner])
        for i, value in enumerate(initial):
            if value:
                body.effect('buffer.store', [view, body.const('usize', i), body.const('u8', value)])
        owners.append(owner)
        views.append(view)
    body.effect('loan.end', [views[0]])
    views[0] = body.value('readbuf', 'borrow.read', [owners[0]])
    result = body.value('u32', 'call', views, {'function': 'f0'})
    observation_size = min(240, output_size)
    observed = [body.value('u8', 'buffer.load', [views[1], body.const('usize', i)]) for i in range(observation_size)]
    for view in views:
        body.effect('loan.end', [view])
    for owner in owners:
        body.effect('owner.drop', [owner])
    source = ('hia-asm.v1 hepta.hia.program.v8 json_arena_reference\n'
              'fn observe() -> (u32,' + ','.join(['u8'] * observation_size) + ') '
              'effects(alloc,read,write,trap) entry(b0)\nblock b0()\n'
              + body.text() + '  ret(' + ','.join([result, *observed]) + ')\nend\n'
              + source_path.read_text().split('\n', 1)[1])
    actual = execute_program(assemble_program(source), 'observe', [], max_steps=2000000)
    if actual['status'] != 'returned':
        raise AssertionError(actual)
    code, *raw = actual['values']
    return code, bytes(raw[:code]) if code <= observation_size else None


class JsonDecodeHiaSourceTests(unittest.TestCase):
    def test_generated_source_exact_and_checked_by_independent_core(self):
        from hepta.hia_agent_assembly import render_assembly, assemble_program
        self.assertEqual(SOURCE.read_text(), render_assembly(document()))
        self.assertEqual(len(assemble_program(SOURCE.read_bytes()).as_dict()['functions']), 15)

    def test_real_vm_tree_and_unicode_before_native_seed(self):
        for wire in (b'null', b'-13', b'[]', b'{}', b'[0,null]', b'{"x":true}',
                     b'"\\ud83d\\ude00"'):
            with self.subTest(wire=wire):
                size, arena = vm_arena(wire)
                self.assertLessEqual(size, 240)
                self.assertEqual(materialize(arena, wire), json.loads(wire))
        self.assertEqual(vm_arena(b'{"a":0,"\\u0061":1}')[0], 0xfffffffc)
        self.assertEqual(vm_arena(b'[0]', nodes=1)[0], 0xfffffffe)
        self.assertEqual(vm_arena(b'"\\ud800"')[0], 0xffffffff)

    def test_default_reference_and_input_validation(self):
        with patch.dict('os.environ', {'HEPTA_HIA_JSON_DECODE_MANIFEST': ''}):
            self.assertEqual(decode_hia_json('{"a":[1,true]}', max_nodes=8, max_depth=2), {'a': [1, True]})
            for options in ({'max_nodes': True, 'max_depth': 1}, {'max_nodes': 8, 'max_depth': -1}):
                with self.assertRaises(ValueError):
                    decode_hia_json('[]', **options)

    def test_bridge_refuses_invalid_headers_ranges_cycles_and_orphan_nodes(self):
        _, arena = vm_arena(b'[0,null]')
        for offset, value in ((0, 0), (8, 1048577), (16, 0), (24, len(arena) + 1),
                              (48, 2), (64, 7), (88, 0), (96, 999999),
                              (128, 2), (136, 1)):
            broken = bytearray(arena)
            struct.pack_into('<Q', broken, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                materialize(bytes(broken), b'[0,null]')


class JsonDecodeHiaNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # An independent interpreter observes the emitted tree before any B0.
        _, arena = vm_arena(b'{"x":true}')
        assert materialize(arena, b'{"x":true}') == {'x': True}
        from tools.qualify_hia_selfhost import build_seed, compile_stage
        cls.temporary = tempfile.TemporaryDirectory(prefix='hia-json-decode-native-')
        folder = Path(cls.temporary.name)
        seed, _ = build_seed(folder)
        source = (ROOT / 'examples/hia_bootstrap/selfhost.hiaasm').read_bytes()
        first, _ = compile_stage(folder, 'B1', seed, source, image_format='seed-shared')
        second, _ = compile_stage(folder, 'B2', first, source)
        assert first.read_bytes() == second.read_bytes()
        image, cls.receipt = compile_stage(folder, 'json-decode', second, SOURCE.read_bytes())
        cls.image = image.read_bytes()
        cls.native = NativeJsonDecoder(cls.image, sha256(cls.image).hexdigest())
        cls.manifest = folder / 'manifest.json'
        cls.manifest.write_text(json.dumps({'schema': SCHEMA, 'source_sha256': sha256(SOURCE.read_bytes()).hexdigest(),
            'image_path': image.name, 'image_sha256': sha256(cls.image).hexdigest(),
            'compiler_sha256': sha256(second.read_bytes()).hexdigest()}))

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def decode(self, wire, nodes=262144, depth=128, **options):
        return self.native.decode(wire, max_nodes=nodes, max_depth=depth, **options)

    def test_native_payload_parse_and_existing_tool_api_without_python_json_decoder(self):
        from hepta.hia_program_tools import decode_json
        installed_decoder(str(self.manifest))
        with patch.dict('os.environ', {'HEPTA_HIA_JSON_DECODE_MANIFEST': str(self.manifest)}):
            with (patch('json.loads', side_effect=AssertionError('host JSON parse')),
                  patch.object(json.JSONDecoder, 'decode', side_effect=AssertionError('host JSON decode'))):
                self.assertEqual(decode_json('{"a":[true,null,-12,"\\u00e9"]}'), {'a': [True, None, -12, 'é']})
        self.assertEqual(self.receipt['forbidden_compiler_modules_loaded'], [])

    def test_all_scalars_unicode_escapes_keys_and_nested_containers(self):
        values = [None, True, False, 0, -1, 2**128, -(2**128), '', 'a\\"\x00é😀',
                  [], {}, {'a': [], 'b': {}, 'c': [0, {'é😀': 'é😀'}]}]
        for cp in (0, 31, 32, 127, 128, 2047, 2048, 55295, 57344, 65535, 65536, 1114111):
            values.extend([chr(cp), {chr(cp): [chr(cp)]}])
        for value in values:
            for escaped in (False, True):
                wire = json.dumps(value, ensure_ascii=escaped).encode()
                with self.subTest(wire=wire):
                    self.assertEqual(self.decode(wire), value)

    def test_two_thousand_random_values_and_byte_exact_integer_lexemes(self):
        rng = random.Random(786433)
        def tree(depth=0):
            if depth < 6 and rng.randrange(3):
                if rng.randrange(2):
                    return [tree(depth + 1) for _ in range(rng.randrange(4))]
                return {f'k{i}é😀': tree(depth + 1) for i in range(rng.randrange(4))}
            return rng.choice([None, True, False, rng.randrange(-2**130, 2**130), 'é😀\x00\\"'])
        for i in range(2000):
            value = tree()
            wire = json.dumps(value, ensure_ascii=bool(i & 1)).encode()
            self.assertEqual(self.decode(wire), value)
        self.assertEqual(self.decode(b'[-0,123456789012345678901234567890]', parse_int=lambda s: s),
                         ['-0', '123456789012345678901234567890'])

    def test_callback_order_is_source_order_postorder_and_failures_propagate(self):
        wire = b'[{"a":1},{"b":{"c":-0}},2]'
        def run(decoder):
            trace = []
            def number(text):
                trace.append(('int', text))
                return int(text)
            def pairs(items):
                trace.append(('object', list(items)))
                return dict(items)
            result = decoder(wire, object_pairs_hook=pairs, parse_int=number)
            return result, trace
        self.assertEqual(run(self.decode), run(json.loads))
        with self.assertRaisesRegex(RuntimeError, 'callback'):
            self.decode(b'1', parse_int=lambda _: (_ for _ in ()).throw(RuntimeError('callback')))

    def test_budget_boundaries_large_wire_and_large_tree(self):
        for depth in (0, 1, 8, 64, 128):
            self.decode(b'[' * depth + b'0' + b']' * depth, depth=depth)
            self.decode(b'[' * (depth + 1) + b']' * (depth + 1), depth=depth)
            with self.assertRaises(OverflowError):
                self.decode(b'[' * (depth + 1) + b'0' + b']' * (depth + 1), depth=depth)
        for nodes in (1, 2, 1024, 1048576):
            good = b'0' if nodes == 1 else b'[' + b','.join([b'0'] * (nodes - 1)) + b']'
            self.decode(good, nodes=nodes)
            with self.assertRaises(OverflowError):
                self.decode(b'[' + b','.join([b'0'] * nodes) + b']', nodes=nodes)
        wire = b'"' + b'a' * ((8 << 20) - 2) + b'"'
        self.assertEqual(len(self.decode(wire)), (8 << 20) - 2)
        with self.assertRaises(ValueError):
            self.decode(wire + b' ')

    def test_invalid_syntax_duplicate_unicode_and_random_mutation_error_parity(self):
        from tests.test_hia_json_preflight_native import reference
        for byte in range(256):
            for wire in (bytes([byte]), b'"' + bytes([byte]) + b'"'):
                expected = reference(wire)
                if expected:
                    with self.assertRaises(ValueError):
                        self.decode(wire)
                else:
                    self.assertEqual(self.decode(wire), json.loads(wire))
        rng = random.Random(104729)
        original = b'{"a":[0,true,false,null,"\\ud83d\\ude00"],"b":{"x":"xyz"}}'
        for _ in range(2000):
            wire = bytearray(original)
            for _ in range(rng.randrange(1, 4)):
                wire[rng.randrange(len(wire))] = rng.randrange(256)
            wire = bytes(wire)
            if reference(wire):
                with self.assertRaises(ValueError):
                    self.decode(wire)
            else:
                self.assertEqual(self.decode(wire), json.loads(wire))
        for wire in (b'{"a":0,"\\u0061":1}', b'{"\\ud83d\\ude00":0,"\xf0\x9f\x98\x80":1}'):
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                self.decode(wire)

    def test_concurrent_private_arenas_and_exact_key_scopes(self):
        wires = [json.dumps({'x': i, 'v': [{'é': i}, {'é': -i}]}).encode() for i in range(64)]
        with ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(list(pool.map(self.decode, wires)), [json.loads(w) for w in wires])
        value = {f'k{i}': i for i in range(16384)}
        self.assertEqual(self.decode(json.dumps(value).encode()), value)

    def test_identity_manifest_and_raw_small_buffer_refusals(self):
        with self.assertRaises(ValueError):
            NativeJsonDecoder(self.image, '0' * 64)
        n = installed_decoder(str(self.manifest))
        for size in (0, 127):
            raw = ctypes.create_string_buffer(256)
            self.assertEqual(n._entry(raw, 0, raw, size, raw, 128), 0xfffffffd)
        with patch.dict('os.environ', {'HEPTA_HIA_JSON_DECODE_MANIFEST': '/missing/manifest'}):
            with self.assertRaises(FileNotFoundError):
                decode_hia_json('[]', max_nodes=32, max_depth=4)
        wrong = json.loads(self.manifest.read_text())
        wrong['source_sha256'] = '0' * 64
        path = self.manifest.with_name('wrong.json')
        path.write_text(json.dumps(wrong))
        with self.assertRaisesRegex(ValueError, 'source identity'):
            installed_decoder(str(path))
