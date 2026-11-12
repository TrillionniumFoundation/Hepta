"""Actual integer-only shortest printing: VM, finite-domain boundaries and ABI."""
import ctypes
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import math
import json
import os
from pathlib import Path
import random
import struct
import tempfile
import unittest

from hepta.hia_agent_binary64_format_native import SOURCE, SCHEMA, SELECTOR, NativeAgentBinary64Format
from tools.generate_hia_agent_binary64_format import document

ROOT = Path(__file__).resolve().parents[1]


def vm_render(wire, checked):
    from hepta.hia_program_runtime import _Machine, _Owner, _View
    owners = [_Owner(-1, bytearray(wire)), _Owner(-2, bytearray(b'\xa5' * 32)),
              _Owner(-3, bytearray(b'\x93' * 8192))]
    machine = _Machine(checked, 50000000, 16 << 20, None, 128)
    entry = checked.as_dict()['functions'][0]
    result = machine.invoke(entry, [_View(owners[0], False), _View(owners[1], True), _View(owners[2], True)])[0]
    return result, bytes(owners[1].data)


class AgentBinary64FormatSourceTests(unittest.TestCase):
    def test_unqualified_builder_refuses_before_output_creation(self):
        from tools.build_hia_agent_binary64_format import build
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); (root/'compiler').write_bytes(b'unqualified'); (root/'cold').write_text('{}')
            with self.assertRaisesRegex(ValueError, 'completed matching-source cold'):
                build(root/'output', root/'compiler', root/'cold')
            self.assertFalse((root/'output').exists())

    def test_generated_source_and_independent_Core_VM_before_native_seed(self):
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        self.assertEqual(SOURCE.read_text(), render_assembly(document()))
        checked = assemble_program(SOURCE.read_bytes())
        for value, expected in [(0., b'0.0'), (-0., b'-0.0'), (1.25, b'1.25')]:
            count, output = vm_render(struct.pack('<d', value), checked)
            self.assertEqual((count, output[:count], output[count:]),
                             (len(expected), expected, b'\xa5' * (32-len(expected))))
        for wire in (b'', b'1234567', struct.pack('<Q', 0x7ff0000000000000)):
            self.assertEqual(vm_render(wire, checked), (0xffffffff, b'\xa5' * 32))


class AgentBinary64FormatNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from hepta.hia_agent_assembly import assemble_program
        assert vm_render(struct.pack('<d', 1.25), assemble_program(SOURCE.read_bytes()))[0] == 4
        from tools.qualify_hia_selfhost import build_seed, compile_stage
        destination = os.environ.get('HEPTA_HIA_AGENT_BINARY64_FORMAT_EVIDENCE')
        cls.temporary = None
        if destination:
            cls.folder = Path(destination); cls.folder.mkdir(mode=0o700)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-binary64-format-')
            cls.folder = Path(cls.temporary.name)
        seed, _ = build_seed(cls.folder)
        compiler = (ROOT / 'examples/hia_bootstrap/selfhost.hepta').read_bytes()
        first, _ = compile_stage(cls.folder, 'B1', seed, compiler, image_format='seed-shared')
        second, _ = compile_stage(cls.folder, 'B2', first, compiler)
        assert first.read_bytes() == second.read_bytes()
        image, cls.receipt = compile_stage(cls.folder, 'binary64-format', second, SOURCE.read_bytes())
        raw = image.read_bytes(); cls.native = NativeAgentBinary64Format(raw, sha256(raw).hexdigest())
        cls.manifest = cls.folder/'format-manifest.json'
        cls.manifest.write_text(json.dumps(dict(schema=SCHEMA, source_sha256=sha256(SOURCE.read_bytes()).hexdigest(),
            image_path=image.name, image_sha256=sha256(raw).hexdigest(), compiler_sha256=sha256(second.read_bytes()).hexdigest())))

    @classmethod
    def tearDownClass(cls):
        if cls.temporary: cls.temporary.cleanup()

    def test_all_binary_exponents_and_adjacent_values_match_independent_host_printer(self):
        values = {0, 1, 2, 3, (1 << 52)-1, 1 << 52, 0x7fefffffffffffff}
        for exponent in range(1, 2047):
            power = exponent << 52
            values.update((power-1, power, power+1))
        for bits in sorted(values):
            for sign in (0, 1 << 63):
                wire = struct.pack('<Q', bits | sign)
                value = struct.unpack('<d', wire)[0]
                with self.subTest(bits=bits | sign):
                    actual = self.native.render_bits(wire)
                    self.assertEqual(actual, repr(value).encode('ascii'))
                    self.assertEqual(struct.pack('<d', float(actual)), wire)

    def test_random_entire_finite_bit_domain_and_decimal_notation_boundaries(self):
        rng = random.Random(6111002)
        values = [1e-4, 1e-5, 1e15, 1e16, 1e20, 1e23, 1e-23, 1e-100,
                  1.0000000000000002, 0.9999999999999999]
        for value in tuple(values):
            values.extend([math.nextafter(value, 0.), math.nextafter(value, math.inf)])
        for _ in range(2048):
            value = struct.unpack('<d', struct.pack('<Q', rng.getrandbits(64)))[0]
            if math.isfinite(value): values.append(value)
        for value in values:
            with self.subTest(reference=repr(value)):
                self.assertEqual(self.native.render(value), repr(value).encode('ascii'))

    def test_native_ABI_atomic_refusals_canaries_and_nonfinite_domain(self):
        cases = [(struct.pack('<d', 1.25), 3, 8192, 0xfffffffe),
                 (struct.pack('<d', 1.25), 32, 8191, 0xfffffffd),
                 (b'1234567', 32, 8192, 0xffffffff)]
        for bits in (0x7ff0000000000000, 0xfff0000000000000, 0x7ff8000000000000,
                     0x7ff0000000000001, 0xffffffffffffffff):
            wire = struct.pack('<Q', bits)
            cases.append((wire, 32, 8192, 0xffffffff))
            with self.assertRaisesRegex(ValueError, 'nonfinite'): self.native.render_bits(wire)
        for wire, capacity, scratch, expected in cases:
            source = ctypes.create_string_buffer(wire)
            output = ctypes.create_string_buffer(b'\xa5' * 64, 64)
            workspace = ctypes.create_string_buffer(b'\x93' * 8224, 8224)
            status = self.native._entry(source, len(wire), output, capacity, workspace, scratch)
            self.assertEqual(status, expected)
            self.assertEqual(output.raw, b'\xa5' * 64)
            self.assertEqual(workspace.raw[scratch:], b'\x93' * (8224-scratch))

    def test_private_concurrent_scratch_no_host_float_format_call(self):
        values = [0., -0., 1.25, 5e-324, 1e16, 1.7976931348623157e308] * 24
        expected = [repr(value).encode() for value in values]
        from unittest.mock import patch
        import hepta.hia_agent_binary64_format_native as bridge
        with patch.object(bridge, 'repr', side_effect=AssertionError('foreign printer'), create=True), \
                patch.object(bridge, 'str', side_effect=AssertionError('foreign printer'), create=True):
            with ThreadPoolExecutor(max_workers=8) as pool:
                self.assertEqual(list(pool.map(self.native.render, values)), expected)

    def test_actual_Agent_wire_and_digest_route_selected_floats_including_keys(self):
        from unittest.mock import patch
        from hepta import hia_agent_store as store
        from hepta.hia_program_tools import bounded_json_wire, HIAEditRejected
        values = [dict(ratio=1.25, zero=-0., tiny=5e-324, huge=1.7976931348623157e308,
                       text='a\n中😀', integer=123456789012345678901234567890),
                  {1.25: 'key', -2.: 'second'}, [-0., 0., 1e16, 1e-5]]
        expected = [store.wire(value) for value in values]
        calls = []
        original = NativeAgentBinary64Format.render
        def render(image, value):
            calls.append(struct.pack('<d', value)); return original(image, value)
        with patch.dict(os.environ, {SELECTOR: str(self.manifest)}), \
                patch.object(NativeAgentBinary64Format, 'render', render), \
                patch.object(json.JSONEncoder, 'iterencode', side_effect=AssertionError('default numeric printer')):
            for value, wire in zip(values, expected):
                self.assertEqual(store.wire(value), wire)
                self.assertEqual(store.digest(value), sha256(wire).hexdigest())
            with self.assertRaises(HIAEditRejected): store.wire({1.25: 1, '1.25': 2})
            for value in [float('inf'), float('-inf'), float('nan'), {float('inf'): 0}]:
                with self.assertRaises(HIAEditRejected): store.wire(value)
            cyclic=[];cyclic.append(cyclic)
            with self.assertRaises(HIAEditRejected):store.wire(cyclic)
        self.assertGreater(len(calls), 20)
        self.assertIn(struct.pack('<d', -0.), calls)
        callback = lambda value: self.native.render(value).decode('ascii')
        self.assertEqual(bounded_json_wire(1.25, 4, float_renderer=callback), b'1.25')
        with self.assertRaises(HIAEditRejected): bounded_json_wire(1.25, 3, float_renderer=callback)

    def test_selected_invalid_or_changed_source_never_falls_back(self):
        from unittest.mock import patch
        from hepta import hia_agent_store as store
        bad = self.folder/'invalid-format-manifest.json'; bad.write_text('{}')
        with patch.dict(os.environ, {SELECTOR: str(bad)}), \
                patch.object(store, 'bounded_json_wire', side_effect=AssertionError('fallback')):
            with self.assertRaises(ValueError): store.wire(1.25)
        from hepta.hia_agent_binary64_format_native import installed_agent_binary64_format
        wrong = self.folder/'wrong-source-format-manifest.json'
        manifest=json.loads(self.manifest.read_text());manifest['source_sha256']='0'*64
        wrong.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, 'source identity mismatch'):
            installed_agent_binary64_format(str(wrong))
