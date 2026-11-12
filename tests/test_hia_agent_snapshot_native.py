"""Actual native snapshot semantics, guarded refusals and hosted caller wiring."""
from concurrent.futures import ThreadPoolExecutor
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import random
import struct
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_agent_buffers as buffers
from hepta.hia_agent_snapshot_native import NativeAgentSnapshot, SOURCE, SCHEMA, transport, installed_snapshot
from hepta.hia_agent_store import AgentRejected
from tools.generate_hia_agent_snapshot import document

ROOT = Path(__file__).resolve().parents[1]


def vm_snapshot(value, materialize=True, output_size=64):
    """Run the HIA program through independent Core semantics, no native seed."""
    from tools.hia_selfhost_bulk import Body
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import execute_program
    wire = transport(value, materialize)
    body = Body(0)
    owners, views = [], []
    for size in (len(wire), output_size, 64):
        owner = body.value('buffer', 'buffer.new', [body.const('usize', size)])
        owners.append(owner)
        views.append(body.value('mutbuf', 'borrow.mut', [owner]))
    for index, val in enumerate(wire):
        if val:
            body.effect('buffer.store', [views[0], body.const('usize', index), body.const('u8', val)])
    for index in range(output_size):
        body.effect('buffer.store', [views[1], body.const('usize', index), body.const('u8', 165)])
    body.effect('loan.end', [views[0]])
    read = body.value('readbuf', 'borrow.read', [owners[0]])
    status = body.value('u32', 'call', [read, views[1], views[2]], {'function': 'f0'})
    observed = [body.value('u8', 'buffer.load', [views[1], body.const('usize', i)]) for i in range(output_size)]
    for view in [read, views[1], views[2]]:
        body.effect('loan.end', [view])
    for owner in owners:
        body.effect('owner.drop', [owner])
    source = ('hia-asm.v1 hepta.hia.program.v8 snapshot_reference\n'
        'fn observe() -> (' + ','.join(['u32'] + ['u8'] * output_size) + ') '
        'effects(alloc,read,write,trap) entry(b0)\nblock b0()\n' + body.text()
        + '  ret(' + ','.join([status, *observed]) + ')\nend\n'
        + SOURCE.read_text().split('\n', 1)[1])
    result = execute_program(assemble_program(source), 'observe', [], max_steps=2000000)
    if result['status'] != 'returned':
        raise AssertionError(result)
    return result['values'][0], bytes(result['values'][1:])


class AgentSnapshotSourceTests(unittest.TestCase):
    def test_all_live_agent_discovery_resources_are_present_and_cold_bound(self):
        from hepta.hia_agent_contract import DISCOVERY_FILES, installation_manifest
        from tools.hia_selfhost_contract import file_digests, CONTRACT_PATH
        files = file_digests()
        identity = installation_manifest()
        self.assertEqual(len(identity['worker_sha256']), 64)
        for name in DISCOVERY_FILES:
            key = 'docs/' + name
            self.assertTrue((ROOT / key).is_file(), key)
            if key != CONTRACT_PATH:
                self.assertEqual(files[key], sha256((ROOT / key).read_bytes()).hexdigest())

    def test_generated_source_and_independent_VM_admission_materialization(self):
        from hepta.hia_agent_assembly import render_assembly
        self.assertEqual(SOURCE.read_text(), render_assembly(document()))
        for value, expected in [({'bytes_hex': '00abff'}, b'\x00\xab\xff'),
                                ({'byte_length': 3, 'fill_byte': 7}, b'\x07' * 3),
                                ({'bytes_hex': ''}, b'')]:
            status, data = vm_snapshot(value)
            self.assertEqual(status, 0)
            self.assertEqual(data[:8], struct.pack('<Q', len(expected)))
            self.assertEqual(data[8:8 + len(expected)], expected)
            self.assertEqual(data[8 + len(expected):], b'\xa5' * (56 - len(expected)))

    def test_independent_VM_refuses_without_publishing_any_output(self):
        for value, expected in [({'bytes_hex': '00aZ'}, 1),
                                ({'byte_length': 1, 'fill_byte': True}, 2),
                                ({'bytes_hex': '', 'extra': 1}, 3), ([], 4)]:
            self.assertEqual(vm_snapshot(value), (expected, b'\xa5' * 64))
        self.assertEqual(vm_snapshot({'bytes_hex': '01'}, output_size=8), (5, b'\xa5' * 8))


class AgentSnapshotNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # The independent interpreter must observe real semantics before B0.
        assert vm_snapshot({'bytes_hex': '012aff'})[:1] == (0,)
        from tools.qualify_hia_selfhost import build_seed, compile_stage
        cls.temporary = tempfile.TemporaryDirectory(prefix='hia-agent-snapshot-')
        folder = Path(cls.temporary.name)
        seed, _ = build_seed(folder)
        source = (ROOT / 'examples/hia_bootstrap/selfhost.hepta').read_bytes()
        first, _ = compile_stage(folder, 'B1', seed, source, image_format='seed-shared')
        second, _ = compile_stage(folder, 'B2', first, source)
        assert first.read_bytes() == second.read_bytes()
        image, cls.receipt = compile_stage(folder, 'agent-snapshot', second, SOURCE.read_bytes())
        cls.image = NativeAgentSnapshot(image.read_bytes(), sha256(image.read_bytes()).hexdigest())
        cls.manifest = folder / 'manifest.json'
        cls.manifest.write_text(json.dumps({'schema': SCHEMA,
            'source_sha256': sha256(SOURCE.read_bytes()).hexdigest(), 'image_path': image.name,
            'image_sha256': sha256(image.read_bytes()).hexdigest(),
            'compiler_sha256': sha256(second.read_bytes()).hexdigest()}))

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def observe(self, function, value):
        try:
            return ('returned', function(value))
        except AgentRejected as error:
            return ('rejected', error.code, str(error))

    def test_exact_reference_errors_types_and_unicode(self):
        cases = [None, [], (), False, {'x': 1}, {}, {'bytes_hex': '', 'extra': 0},
            {'bytes_hex': None}, {'bytes_hex': 'Ab'}, {'bytes_hex': '01 '},
            {'bytes_hex': '0'}, {'bytes_hex': 'ä0'}, {'bytes_hex': '\ud800'},
            {'bytes_hex': '😀' * ((1 << 19) + 1)},
            {'byte_length': True, 'fill_byte': 0}, {'byte_length': 0, 'fill_byte': False},
            {'byte_length': -1, 'fill_byte': 0}, {'byte_length': 1 << 99, 'fill_byte': 0},
            {'byte_length': 0.0, 'fill_byte': 0}, {'byte_length': 0, 'fill_byte': 256},
            {'byte_length': 0, 'fill_byte': -1}, {'byte_length': (1 << 20) + 1, 'fill_byte': 0},
            {'bytes_hex': ''}, {'byte_length': 0, 'fill_byte': 255}]
        for value in cases:
            with self.subTest(value=repr(value)[:100]):
                self.assertEqual(self.observe(self.image.evaluate, value), self.observe(buffers._buffer_size_reference, value))
                self.assertEqual(self.observe(lambda x: self.image.evaluate(x, materialize=True), value),
                                 self.observe(buffers._buffer_bytes_reference, value))

    def test_five_hundred_generated_descriptors_and_both_field_orders(self):
        rng = random.Random(6476198178)
        for _ in range(500):
            data = rng.randbytes(rng.randrange(1024))
            valid = {'bytes_hex': data.hex()}
            self.assertEqual(self.image.evaluate(valid), len(data))
            self.assertEqual(self.image.evaluate(valid, materialize=True), data)
            size, fill = rng.randrange(1024), rng.randrange(256)
            for value in ({'byte_length': size, 'fill_byte': fill}, {'fill_byte': fill, 'byte_length': size}):
                self.assertEqual(self.image.evaluate(value, materialize=True), bytes([fill]) * size)
            bad = {'bytes_hex': data.hex() + rng.choice(['Z0', '00 ', 'a', '０0'])}
            self.assertEqual(self.observe(self.image.evaluate, bad), self.observe(buffers._buffer_size_reference, bad))

    def test_full_extent_and_actual_hosted_callers_without_reference_materializer(self):
        with patch.dict(os.environ, {'HEPTA_HIA_AGENT_SNAPSHOT_MANIFEST': str(self.manifest)}), \
             patch.object(buffers, '_buffer_size_reference', side_effect=AssertionError('foreign admission')), \
             patch.object(buffers, '_buffer_bytes_reference', side_effect=AssertionError('foreign materialization')):
            for value in [{'bytes_hex': 'ab' * (1 << 20)}, {'byte_length': 1 << 20, 'fill_byte': 171}]:
                self.assertEqual(buffers.buffer_size(value), 1 << 20)
                self.assertEqual(buffers.buffer_bytes(value), b'\xab' * (1 << 20))
            signature = {'params': ['readbuf'], 'abi': buffers.PROFILE, 'max_buffer_bytes': 20}
            self.assertEqual(buffers.validate_arguments(signature, [{'bytes_hex': '00ff'}]), 2)
            with self.assertRaises(AgentRejected):
                buffers.validate_arguments(signature, [{'byte_length': 21, 'fill_byte': 0}])

    def raw(self, wire, capacity):
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        output = ctypes.create_string_buffer(b'\xa5' * max(1, capacity), max(1, capacity))
        scratch = ctypes.create_string_buffer(64)
        result = self.image._entry(source, len(wire), output, capacity, scratch, 64)
        return result, output.raw

    def test_malformed_wire_and_real_output_capacity_leave_guards_unchanged(self):
        valid = transport({'bytes_hex': '00ff'}, True)
        for wire in [valid[:31], valid[:-1], valid + b'x',
                     struct.pack('<QQQQ', 9, 1, 1, 1),
                     struct.pack('<QQQQ', 1, 2, 1, 1)]:
            self.assertEqual(self.raw(wire, 64), (4294967293, b'\xa5' * 64))
        for size in (0, 1, 7, 8, 9):
            self.assertEqual(self.raw(valid, size), (5, b'\xa5' * max(1, size)))
        # Duplicate fields and late invalid hex must not publish even a length.
        duplicate = struct.pack('<QQQQ', 1, 1, 1, 2) + valid[32:] + valid[32:]
        self.assertEqual(self.raw(duplicate, 64), (3, b'\xa5' * 64))
        self.assertEqual(self.raw(transport({'bytes_hex': '0000fg'}, True), 64), (1, b'\xa5' * 64))

    def test_private_concurrency_and_selected_manifest_failure_is_not_fallback(self):
        values = [{'byte_length': n, 'fill_byte': n % 256} for n in range(64)]
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda x: self.image.evaluate(x, materialize=True), values))
        self.assertEqual(results, [bytes([n % 256]) * n for n in range(64)])
        original = self.manifest.read_bytes()
        try:
            value = json.loads(original)
            value['source_sha256'] = '0' * 64
            self.manifest.write_text(json.dumps(value))
            with patch.dict(os.environ, {'HEPTA_HIA_AGENT_SNAPSHOT_MANIFEST': str(self.manifest)}), \
                 patch.object(buffers, '_buffer_bytes_reference', side_effect=AssertionError('fallback')):
                with self.assertRaisesRegex(ValueError, 'source identity'):
                    buffers.buffer_bytes({'bytes_hex': '00'})
        finally:
            self.manifest.write_bytes(original)
        self.assertEqual(installed_snapshot(str(self.manifest)).evaluate({'bytes_hex': '00'}), 1)

    def test_invalid_native_result_is_not_reinterpreted_as_a_descriptor_refusal(self):
        original = self.image._entry
        try:
            self.image._entry = lambda *_args: 0xDEADBEEF
            with self.assertRaisesRegex(RuntimeError, 'protocol buffers'):
                self.image.evaluate({'bytes_hex': '00'})
            def corrupt_length(_source, _size, output, *_rest):
                ctypes.memmove(output, struct.pack('<Q', (1 << 20) + 1), 8)
                return 0
            self.image._entry = corrupt_length
            with self.assertRaisesRegex(RuntimeError, 'result length'):
                self.image.evaluate({'bytes_hex': '00'})
        finally:
            self.image._entry = original
