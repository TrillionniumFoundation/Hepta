"""Actual composed Agent arena-to-wire owner: VM, native bytes and refusal controls."""
from concurrent.futures import ThreadPoolExecutor
import ctypes
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import random
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_agent_json_wire_native import (
    SOURCE, SCHEMA, MAX_BYTES, MAX_NODES, MAX_DEPTH, PRIVATE_BYTES, REQUEST_MAGIC,
    NONE, BAD_ABI, BAD_ARENA, NONFINITE, INTEGER_LIMIT, OUTPUT_LIMIT,
    NativeAgentJsonWire, request_state, installed_agent_json_wire)
from hepta.hia_agent_data_json_native import SOURCE as DATA_SOURCE, NativeAgentDataJson
from hepta.hia_program_tools import bounded_json_wire, HIAEditRejected

ROOT = Path(__file__).resolve().parents[1]


def reference(value):
    return bounded_json_wire(value, MAX_BYTES, ensure_ascii=False, sort_keys=True)


def checked_sources():
    from hepta.hia_agent_assembly import assemble_program
    return assemble_program(DATA_SOURCE.read_bytes()), assemble_program(SOURCE.read_bytes())


def vm_composed(wire, checked=None):
    """Run both original producer and new writer in the independent Core VM."""
    from hepta.hia_json_decode_native import arena_sizes
    from hepta.hia_program_runtime import _Machine, _Owner, _View
    decoder, writer = checked_sources() if checked is None else checked
    output_size, workspace_size = arena_sizes(len(wire), MAX_NODES, MAX_DEPTH)
    work = bytearray(workspace_size)
    struct.pack_into('<QQ', work, 48, MAX_NODES, MAX_DEPTH)
    owners = [_Owner(-1, bytearray(wire)), _Owner(-2, bytearray(output_size)), _Owner(-3, work)]
    machine = _Machine(decoder, 100000000, 64 << 20, None, 128)
    result = machine.invoke(decoder.as_dict()['functions'][0],
        [_View(owners[0], False), _View(owners[1], True), _View(owners[2], True)])[0]
    if not 120 <= result <= output_size:
        raise AssertionError(('actual VM decoder refused', result))
    arena = bytes(owners[1].data[:result])
    state, private = request_state(wire, arena, 0)
    owners = [_Owner(-1, bytearray(wire)), _Owner(-2, bytearray(b'\xa5' * MAX_BYTES)),
              _Owner(-3, bytearray(state.raw))]
    machine = _Machine(writer, 100000000, 64 << 20, None, 128)
    count = machine.invoke(writer.as_dict()['functions'][0],
        [_View(owners[0], False), _View(owners[1], True), _View(owners[2], True)])[0]
    if bytes(owners[0].data) != wire:
        raise AssertionError('writer changed its read-only input')
    status, failed = struct.unpack_from('<QQ', owners[2].data, private + 16048)
    return count, bytes(owners[1].data), status, failed


class AgentJsonWireSourceTests(unittest.TestCase):
    def test_generated_source_and_original_profile(self):
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        from tools import generate_hia_agent_json_wire as generator
        model = generator.document()
        self.assertEqual(SOURCE.read_text(), render_assembly(model))
        checked = assemble_program(SOURCE.read_bytes())
        self.assertLessEqual(len(checked.as_dict()['functions']), 128)
        self.assertTrue(generator.NUMERIC_AUDIT['inverse_AST_equal'])
        self.assertEqual(generator.NUMERIC_AUDIT['numeric_functions'], 18)
        self.assertEqual(len(generator.NUMERIC_AUDIT['shared_functions']), 9)

    def test_independent_VM_producer_and_writer_before_native_compilation(self):
        checked = checked_sources()
        for wire, expected in (
                (b'{"z":1.25,"a":-0}', b'{"a":0,"z":1.25}'),
                ('{"z":-0.0,"a":[true,null,"é\\n",false]}'.encode(),
                 '{"a":[true,null,"é\\n",false],"z":-0.0}'.encode()),
                (b'{"z":[],"a":{}}', b'{"a":{},"z":[]}')):
            with self.subTest(wire=wire):
                count, output, status, failed = vm_composed(wire, checked)
                self.assertEqual((count, output[:count], status, failed),
                                 (len(expected), expected, 0, NONE))
                self.assertEqual(output[count:], b'\xa5' * (MAX_BYTES - count))

    def test_unqualified_builder_refuses_before_output_creation(self):
        from tools.build_hia_agent_json_wire import build
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'compiler').write_bytes(b'unqualified')
            (root / 'cold').write_text('{}')
            with self.assertRaisesRegex(ValueError, 'completed matching-source cold'):
                build(root / 'output', root / 'compiler', root / 'cold')
            self.assertFalse((root / 'output').exists())


class AgentJsonWireNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # An interpreter witness is required before any seed or image compilation.
        count, output, status, failed = vm_composed(b'{"z":1.25,"a":-0}')
        assert (count, output[:count], status, failed) == (16, b'{"a":0,"z":1.25}', 0, NONE)
        from tools.qualify_hia_selfhost import build_seed, compile_stage
        destination = os.environ.get('HEPTA_HIA_AGENT_JSON_WIRE_EVIDENCE')
        cls.temporary = None
        if destination:
            cls.folder = Path(destination)
            cls.folder.mkdir(mode=0o700)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-agent-json-wire-')
            cls.folder = Path(cls.temporary.name)
        selected = os.environ.get('HEPTA_HIA_AGENT_JSON_WIRE_DEVELOPMENT_COMPILER')
        selected_sha = os.environ.get('HEPTA_HIA_AGENT_JSON_WIRE_DEVELOPMENT_COMPILER_SHA256')
        if selected is not None or selected_sha is not None:
            if not selected or not selected_sha:
                raise ValueError('complete explicit development compiler identity required')
            compiler = Path(selected)
            compiler_bytes = compiler.read_bytes()
            if sha256(compiler_bytes).hexdigest() != selected_sha:
                raise ValueError('development compiler differs')
            compiler_kind = 'EXPLICIT_DEVELOPMENT_NOT_COLD_QUALIFICATION'
        else:
            seed, _ = build_seed(cls.folder)
            source = (ROOT / 'examples/hia_bootstrap/selfhost.hepta').read_bytes()
            first, _ = compile_stage(cls.folder, 'B1', seed, source, image_format='seed-shared')
            compiler, _ = compile_stage(cls.folder, 'B2', first, source)
            assert first.read_bytes() == compiler.read_bytes()
            compiler_bytes = compiler.read_bytes()
            compiler_kind = 'DEVELOPMENT_FIXED_POINT_NOT_COLD_QUALIFICATION'
        writer_source = SOURCE.read_bytes()
        decoder_source = DATA_SOURCE.read_bytes()
        image, writer_receipt = compile_stage(cls.folder, 'agent-json-wire', compiler, writer_source)
        decoder_image, decoder_receipt = compile_stage(cls.folder, 'agent-data-json', compiler, decoder_source)
        if (compiler.read_bytes() != compiler_bytes or SOURCE.read_bytes() != writer_source
                or DATA_SOURCE.read_bytes() != decoder_source):
            raise ValueError('development composition custody changed')
        raw = image.read_bytes()
        cls.native = NativeAgentJsonWire(raw, sha256(raw).hexdigest())
        raw_decoder = decoder_image.read_bytes()
        cls.decoder = NativeAgentDataJson(raw_decoder, sha256(raw_decoder).hexdigest())
        cls.manifest = cls.folder / 'manifest.json'
        cls.manifest.write_text(json.dumps(dict(schema=SCHEMA,
            source_sha256=sha256(writer_source).hexdigest(), image_path=image.name,
            image_sha256=sha256(raw).hexdigest(), compiler_sha256=sha256(compiler_bytes).hexdigest())))
        (cls.folder / 'development-build.json').write_text(json.dumps(dict(
            status=compiler_kind, writer_compile_receipt=writer_receipt,
            decoder_compile_receipt=decoder_receipt, independent_VM_before_native=True,
            whole_native_delivery_qualified=False, ordinary_provider_selected=False), indent=2))

    @classmethod
    def tearDownClass(cls):
        if cls.temporary:
            cls.temporary.cleanup()

    def arena(self, wire):
        return self.decoder.arena(wire, max_nodes=MAX_NODES, max_depth=MAX_DEPTH)

    def render(self, wire, **kwargs):
        return self.native.render_decoded(wire, self.decoder, **kwargs)

    def test_complete_scalar_container_unicode_and_key_order_bytes(self):
        values = [None, False, True, 0, -1, 123456789012345678901234567890,
            0.0, -0.0, 1.25, 1e-7, 1e16, 5e-324, [], {}, '',
            ''.join(chr(n) for n in range(32)) + '"\\ /é汉字😀\u2028\u2029',
            {'z': [True, None, {'c': -0.0, 'b': ['é', 2.0]}], 'a': 1},
            {'😀': 1, '\ue000': 2, 'é': 3, 'a': 4, '汉': 5}]
        for value in values:
            raw = json.dumps(value, ensure_ascii=True, sort_keys=False, separators=(', ', ': ')).encode()
            expected = reference(value)
            arena = self.arena(raw)
            before = sha256(raw + arena).hexdigest()
            with self.subTest(raw=raw[:120]):
                self.assertEqual(self.native.render_arena(raw, arena), expected)
                self.assertEqual(sha256(raw + arena).hexdigest(), before)
        self.assertEqual(self.render(b'[-0,-0.0,0e99,-0e99]'), b'[0,-0.0,0.0,-0.0]')
        self.assertEqual(self.render(b'{"\\u0062":2,"a":1}'), b'{"a":1,"b":2}')

    def test_composed_exact_numeric_midpoints_and_sticky_tails(self):
        from tests.test_hia_agent_binary64_native import midpoint_cases
        for raw_number, bits in midpoint_cases():
            raw = b'[' + raw_number + b']'
            with self.subTest(number=raw_number[:32], bits=bits):
                if bits & 0x7fffffffffffffff == 0x7ff0000000000000:
                    result, output, node = self.native.diagnostic(raw, self.arena(raw))
                    self.assertEqual((result, output, node), (NONFINITE, b'', 1))
                else:
                    value = struct.unpack('<d', struct.pack('<Q', bits))[0]
                    self.assertEqual(self.render(raw), b'[' + repr(value).encode() + b']')

    def test_composed_numeric_corpus_complete_wire(self):
        numbers = [b'0e999999999999999999', b'-0e-99999999999999999', b'1e-99999',
            b'5e-324', b'2.2250738585072014e-308', b'1.7976931348623157e308',
            b'1e-7', b'1e16', b'1e15', b'0.00001', b'-1.0000000000000002',
            b'0.' + b'0' * 4096 + b'1e4097']
        rng = random.Random(7612)
        for _ in range(128):
            bits = rng.randrange(1 << 64)
            value = struct.unpack('<d', struct.pack('<Q', bits))[0]
            if math.isfinite(value):
                numbers.append(repr(value).encode())
            size = rng.randrange(1, 180)
            coefficient = str(rng.randrange(1, 10)) + ''.join(str(rng.randrange(10)) for _ in range(size - 1))
            numbers.append((coefficient + 'e' + str(rng.randrange(-size - 330, 310 - size))).encode())
        for number in numbers:
            value = float(number)
            raw = b'{"z":' + number + b',"a":[null,true]}'
            with self.subTest(number=number[:60]):
                if math.isfinite(value):
                    self.assertEqual(self.render(raw), reference({'z': value, 'a': [None, True]}))
                else:
                    self.assertEqual(self.native.diagnostic(raw, self.arena(raw))[0], NONFINITE)

    def test_no_host_JSON_parser_materializer_number_converter_or_encoder(self):
        from hepta import hia_agent_data_json_native as data
        from hepta import hia_agent_binary64_native as decimal
        from hepta import hia_agent_binary64_format_native as formatting
        raw = '{"z":[-0.0,5e-324,1e-7,"é\\n"],"a":{"b":true}}'.encode()
        expected = reference(json.loads(raw))
        def absent(*args, **kwargs):
            raise AssertionError('hosted JSON/numeric owner was called')
        with patch.object(json, 'loads', absent), patch.object(json.JSONDecoder, 'decode', absent), \
                patch.object(json.JSONEncoder, 'iterencode', absent), \
                patch.object(data, 'materialize_data', absent), \
                patch.object(data, 'finite_float', absent), \
                patch.object(decimal.NativeAgentBinary64, 'convert', absent), \
                patch.object(formatting.NativeAgentBinary64Format, 'render', absent):
            self.assertEqual(self.render(raw), expected)

    def test_integer_repr_limit_uses_actual_setting_and_sorted_output_order(self):
        original = sys.get_int_max_str_digits()
        raw = b'{"z":' + b'1' * 641 + b',"a":' + b'2' * 642 + b'}'
        arena = self.arena(raw)
        try:
            sys.set_int_max_str_digits(0)
            value = json.loads(raw)
            expected = reference(value)
            self.assertEqual(self.native.render_arena(raw, arena), expected)
            sys.set_int_max_str_digits(640)
            with self.assertRaises(HIAEditRejected) as reference_error:
                reference(value)
            result, output, failed = self.native.diagnostic(raw, arena)
            self.assertEqual((result, output, failed), (INTEGER_LIMIT, b'', 2))
            with self.assertRaises(HIAEditRejected) as native_error:
                self.native.render_arena(raw, arena)
            self.assertEqual(str(native_error.exception), str(reference_error.exception))
            boundary = b'[' + b'1' * 640 + b']'
            self.assertEqual(self.render(boundary), boundary)
            self.assertEqual(self.render(b'[-0]'), b'[0]')
            # The public method observes the setting afresh for this call.
            sys.set_int_max_str_digits(0)
            self.assertEqual(self.native.render_arena(raw, arena), expected)
        finally:
            sys.set_int_max_str_digits(original)

    def test_numeric_prepass_retains_original_node_order(self):
        for raw in (b'{"z":1e400,"a":2e400}', b'{"a":2e400,"z":1e400}',
                    b'[{"z":-1e400},1e400]'):
            with self.subTest(raw=raw):
                result, output, node = self.native.diagnostic(raw, self.arena(raw))
                expected_node = 2 if raw.startswith(b'[') else 1
                self.assertEqual((result, output, node), (NONFINITE, b'', expected_node))

    def test_exact_byte_ceiling_and_native_output_overflow(self):
        raw = b'"' + b'a' * (MAX_BYTES - 2) + b'"'
        self.assertEqual(self.render(raw), raw)
        with self.assertRaises(ValueError):
            self.render(raw + b' ')
        prefix, suffix = b'{"a":[1e-7,1e-7,1e-7],"z":"', b'"}'
        raw = prefix + b'a' * (MAX_BYTES - len(prefix) - len(suffix)) + suffix
        value = json.loads(raw)
        with self.assertRaises(HIAEditRejected) as reference_error:
            reference(value)
        arena = self.arena(raw)
        result, output, _ = self.native.diagnostic(raw, arena)
        self.assertEqual((result, output), (OUTPUT_LIMIT, b''))
        with self.assertRaises(HIAEditRejected) as native_error:
            self.native.render_arena(raw, arena)
        self.assertEqual(str(native_error.exception), str(reference_error.exception))

    def test_complete_node_and_depth_boundaries_from_actual_producer(self):
        raw = b'[' + b'0,' * (MAX_NODES - 2) + b'0]'
        expected = reference([0] * (MAX_NODES - 1))
        self.assertEqual(expected, raw)
        self.assertEqual(self.render(raw), expected)
        too_many = b'[' + b'0,' * (MAX_NODES - 1) + b'0]'
        with self.assertRaises(OverflowError):
            self.arena(too_many)
        raw = b'[' * MAX_DEPTH + b'0' + b']' * MAX_DEPTH
        value = json.loads(raw)
        self.assertEqual(self.render(raw), reference(value))
        with self.assertRaises(OverflowError):
            self.arena(b'[' + raw + b']')

    def guarded(self, raw, arena, *, output_size=MAX_BYTES, state_delta=0, magic=REQUEST_MAGIC):
        state, private = request_state(raw, arena, 0)
        size = len(state)
        source = ctypes.create_string_buffer(b'\x71' * 32 + raw + b'\x71' * 32, len(raw) + 64)
        output = ctypes.create_string_buffer(b'\xa5' * (MAX_BYTES + 64), MAX_BYTES + 64)
        workspace = ctypes.create_string_buffer(b'\x93' * (size + 64), size + 64)
        ctypes.memmove(ctypes.byref(workspace, 32), arena, len(arena))
        struct.pack_into('<6Q', workspace, 32 + private + 16000, magic, 1, MAX_BYTES, 0, 0, 0)
        result = self.native._entry(ctypes.byref(source, 32), len(raw),
            ctypes.byref(output, 32), output_size,
            ctypes.byref(workspace, 32), size + state_delta)
        self.assertEqual(source.raw, b'\x71' * 32 + raw + b'\x71' * 32)
        self.assertEqual(output.raw[:32] + output.raw[32 + output_size:],
                         b'\xa5' * (MAX_BYTES + 64 - output_size))
        self.assertEqual(workspace.raw[:32] + workspace.raw[size + 32:], b'\x93' * 64)
        return result, output.raw[32:32 + MAX_BYTES], workspace.raw[32:32 + size]

    def test_dirty_numeric_workspace_and_actual_capacity_canaries(self):
        raw = b'{"z":[1.25,-0.0,5e-324,1e-7],"a":"x"}'
        arena = self.arena(raw)
        result, output, _ = self.guarded(raw, arena)
        expected = reference(json.loads(raw))
        self.assertEqual((result, output[:result]), (len(expected), expected))
        self.assertEqual(output[result:], b'\xa5' * (MAX_BYTES - result))
        for kwargs in ({'output_size': MAX_BYTES - 1}, {'state_delta': -1}, {'magic': 0}):
            with self.subTest(kwargs=kwargs):
                result, output, _ = self.guarded(raw, arena, **kwargs)
                self.assertEqual((result, output), (BAD_ABI, b'\xa5' * MAX_BYTES))

    def test_malformed_arena_ownership_spans_and_duplicate_keys_before_output(self):
        raw = b'{"x":[1,2],"y":"ok"}'
        original = self.arena(raw)
        base, = struct.unpack_from('<Q', original, 16)
        count, = struct.unpack_from('<Q', original, 8)
        self.assertEqual(count, 5)
        corruptions = [
            ('magic', 0, 0), ('empty count', 8, 0), ('base', 16, base + 1),
            ('used', 24, len(original) + count * 8 + 1),
            ('end', 32, len(original) - 1), ('raw size', 40, len(raw) + 1),
            ('version', 48, 2), ('reserved', 56, 1),
            ('root parent', 64 + 8, 0), ('unknown kind', 64, 8),
            ('root child', 64 + 24, 0),
            ('self parent', 64 + 56 + 8, 1),
            ('sibling cycle', 64 + 56 + 16, 1),
            ('missing linked child', 64 + 32, 1),
            ('string span', 64 + 4 * 56 + 24, 0)]
        first_key, = struct.unpack_from('<Q', original, 64 + 56 + 40)
        corruptions.append(('duplicate decoded key', 64 + 4 * 56 + 40, first_key))
        for label, at, value in corruptions:
            arena = bytearray(original)
            struct.pack_into('<Q', arena, at, value)
            with self.subTest(label=label):
                result, output, _ = self.guarded(raw, bytes(arena))
                self.assertEqual((result, output), (BAD_ARENA, b'\xa5' * MAX_BYTES))
        arena = bytearray(original)
        arena[first_key] = 255
        result, output, _ = self.guarded(raw, bytes(arena))
        self.assertEqual((result, output), (BAD_ARENA, b'\xa5' * MAX_BYTES))
        self.assertEqual(self.arena(raw), original)

    def test_shared_immutable_arena_concurrent_private_state(self):
        raw = '{"z":[-0.0,1e-7,5e-324,"é"],"a":{"z":2,"b":true}}'.encode()
        arena = self.arena(raw)
        original = sha256(raw + arena).hexdigest()
        expected = reference(json.loads(raw))
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: self.native.render_arena(raw, arena), range(32)))
        self.assertEqual(results, [expected] * 32)
        self.assertEqual(sha256(raw + arena).hexdigest(), original)

    def test_standard_manifest_binding_and_warm_source_recheck(self):
        from hepta import hia_agent_json_wire_native as module
        selected = installed_agent_json_wire(str(self.manifest))
        self.assertEqual(selected.render_decoded(b'{"z":1.25,"a":-0}', self.decoder),
                         b'{"a":0,"z":1.25}')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source.hepta'
            source.write_bytes(SOURCE.read_bytes())
            value = json.loads(self.manifest.read_text())
            image = (self.manifest.parent / value['image_path']).read_bytes()
            (root / 'image.bin').write_bytes(image)
            value['image_path'] = 'image.bin'
            manifest = root / 'manifest.json'
            manifest.write_text(json.dumps(value))
            with patch.object(module, 'SOURCE', source):
                mapped = installed_agent_json_wire(str(manifest))
                self.assertEqual(mapped.render_decoded(b'[1.25]', self.decoder), b'[1.25]')
                source.write_bytes(source.read_bytes() + b'\n')
                with self.assertRaisesRegex(ValueError, 'source identity'):
                    installed_agent_json_wire(str(manifest))
                source.write_bytes(SOURCE.read_bytes())
                # A different manifest key must validate the bytes it is mapping.
                (root / 'image.bin').write_bytes(image[:-1] + bytes([image[-1] ^ 1]))
                second = root / 'second.json'
                second.write_text(json.dumps(value))
                with self.assertRaisesRegex(ValueError, 'executable identity'):
                    installed_agent_json_wire(str(second))
                (root / 'invalid.json').write_text('{}')
                with self.assertRaises(ValueError):
                    installed_agent_json_wire(str(root / 'invalid.json'))


if __name__ == '__main__':
    unittest.main()
