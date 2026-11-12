"""Incremental HIA SHA-256: independent VM, bootstrap, state and partition checks."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
import ctypes
from hashlib import sha256
import json
from pathlib import Path
import random
import struct
import tempfile
import unittest
from unittest.mock import patch
from hepta.hia_sha256_stream_native import (NativeSha256Stream, SOURCE,
    STATE_BYTES, MAX_CHUNK, MAX_TOTAL, installed_stream_hasher)
from tools.generate_hia_sha256_stream import document
from tests.test_hia_sha256_native import VECTORS

ROOT = Path(__file__).resolve().parents[1]


def vm_stream(chunks):
    from tools.hia_selfhost_bulk import Body
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import execute_program
    body = Body(0)
    owners, views = [], []
    for size in (32, STATE_BYTES):
        owner = body.value('buffer', 'buffer.new', [body.const('usize', size)])
        owners.append(owner)
        views.append(body.value('mutbuf', 'borrow.mut', [owner]))
    results = []
    for wire in [b'\x00', *[b'\x01' + c for c in chunks], b'\x02']:
        owner = body.value('buffer', 'buffer.new', [body.const('usize', len(wire))])
        view = body.value('mutbuf', 'borrow.mut', [owner])
        for i, value in enumerate(wire):
            if value:
                body.effect('buffer.store', [view, body.const('usize', i), body.const('u8', value)])
        body.effect('loan.end', [view])
        read = body.value('readbuf', 'borrow.read', [owner])
        results.append(body.value('u32', 'call', [read, *views], {'function': 'f0'}))
        body.effect('loan.end', [read])
        body.effect('owner.drop', [owner])
    observed = [body.value('u8', 'buffer.load', [views[0], body.const('usize', i)]) for i in range(32)]
    for view in views:
        body.effect('loan.end', [view])
    for owner in owners:
        body.effect('owner.drop', [owner])
    source = ('hia-asm.v1 hepta.hia.program.v8 stream_reference\n'
        'fn observe() -> (' + ','.join(['u32'] * len(results) + ['u8'] * 32) + ') '
        'effects(alloc,read,write,trap) entry(b0)\nblock b0()\n' + body.text()
        + '  ret(' + ','.join([*results, *observed]) + ')\nend\n'
        + SOURCE.read_text().split('\n', 1)[1])
    actual = execute_program(assemble_program(source), 'observe', [], max_steps=2000000)
    if actual['status'] != 'returned':
        raise AssertionError(actual)
    assert actual['values'][:len(results)] == [0] * (len(results) - 1) + [32], actual
    return bytes(actual['values'][len(results):])


class Sha256StreamSourceTests(unittest.TestCase):
    def test_generated_source_and_independent_VM_chunk_transitions(self):
        from hepta.hia_agent_assembly import render_assembly
        self.assertEqual(SOURCE.read_text(), render_assembly(document()))
        for chunks in ([], [b'a', b'', b'bc'], [b'a' * 55, b'b'], [b'a' * 63, b'b', b'c']):
            self.assertEqual(vm_stream(chunks), sha256(b''.join(chunks)).digest())


class Sha256StreamNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # A sequence executes in the independent VM before any native seed.
        assert vm_stream([b'a', b'bc']).hex() == VECTORS[1][1]
        from tools.qualify_hia_selfhost import build_seed, compile_stage
        cls.temporary = tempfile.TemporaryDirectory(prefix='hia-sha256-stream-')
        folder = Path(cls.temporary.name)
        seed, _ = build_seed(folder)
        source = (ROOT / 'examples/hia_bootstrap/selfhost.hepta').read_bytes()
        first, _ = compile_stage(folder, 'B1', seed, source, image_format='seed-shared')
        second, _ = compile_stage(folder, 'B2', first, source)
        assert first.read_bytes() == second.read_bytes()
        image, cls.receipt = compile_stage(folder, 'sha256-stream', second, SOURCE.read_bytes())
        cls.image = NativeSha256Stream(image.read_bytes(), sha256(image.read_bytes()).hexdigest())
        cls.manifest = folder / 'manifest.json'
        cls.manifest.write_text(json.dumps({'schema':'hepta.hia.sha256-stream-native.v1',
            'source_sha256':sha256(SOURCE.read_bytes()).hexdigest(), 'image_path':image.name,
            'image_sha256':sha256(image.read_bytes()).hexdigest(),
            'compiler_sha256':sha256(second.read_bytes()).hexdigest()}))

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_FIPS_padding_splits_and_digest_is_reusable(self):
        for wire, expected in VECTORS:
            for step in (1, 7, 55, 56, 63, 64, 65):
                state = self.image.new()
                for offset in range(0, len(wire), step):
                    state.update(wire[offset:offset+step])
                self.assertEqual(state.hexdigest(), expected)
                self.assertEqual(state.hexdigest(), expected)
                copied = state.copy()
                copied.update(b'tail')
                self.assertEqual(copied.digest(), sha256(wire + b'tail').digest())
                self.assertEqual(state.hexdigest(), expected)
                state.update(b'!')
                self.assertEqual(state.digest(), sha256(wire + b'!').digest())
        for size in (0, 1, 54, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 129, 255, 256):
            wire = bytes((i * 137 + 29) & 255 for i in range(size))
            for split in range(size+1):
                state = self.image.new(wire[:split]); state.update(wire[split:])
                self.assertEqual(state.digest(), sha256(wire).digest())
        state = self.image.new()
        for _ in range(1000): state.update(b'a' * 1000)
        self.assertEqual(state.hexdigest(), 'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0')
        self.assertEqual(self.receipt['forbidden_compiler_modules_loaded'], [])

    def test_one_thousand_random_partitions(self):
        rng = random.Random(0x256517)
        for _ in range(1000):
            wire = rng.randbytes(rng.randrange(2049))
            state = self.image.new(); position = 0
            while position < len(wire):
                end = position + rng.randrange(1, 131)
                state.update(wire[position:end]); position = end
                if rng.randrange(16) == 0:
                    self.assertEqual(state.digest(), sha256(wire[:position]).digest())
            self.assertEqual(state.digest(), sha256(wire).digest())

    def test_beyond_old_one_shot_limit_private_concurrency_and_no_foreign_hash(self):
        wire = b'\x00\x80\xff.' * ((MAX_CHUNK + 192) // 4)
        expected = sha256(wire).digest()
        with patch('hepta.hia_sha256_native._foreign_sha256', side_effect=AssertionError('foreign payload hash')):
            with patch.dict('os.environ', {'HEPTA_HIA_SHA256_STREAM_MANIFEST': str(self.manifest)}):
                from hepta.hia_sha256_native import payload_sha256
                self.assertEqual(payload_sha256(wire), expected)
                self.assertEqual(payload_sha256(b'abc').hex(), VECTORS[1][1])
        wires = [bytes([i]) * (i * 29) for i in range(64)]
        with ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(list(pool.map(self.image.digest, wires)), [sha256(w).digest() for w in wires])

    def raw(self, wire, state, *, source_size=None, output_size=32, state_size=STATE_BYTES):
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        output = ctypes.create_string_buffer(b'\xa5' * 40, 40)
        code = self.image._entry(source, len(wire) if source_size is None else source_size,
            output, output_size, state, state_size)
        self.assertEqual(source.raw[:len(wire)], wire)
        self.assertEqual(output.raw[32:], b'\xa5' * 8)
        return code, output.raw

    def test_invalid_protocol_lengths_and_states_refuse_before_any_write(self):
        initial = self.image.new(b'a')._state.raw
        for wire, kwargs, changed in (
            (b'', {}, None), (b'\x00x', {}, None), (b'\x02x', {}, None),
            (b'\x03', {}, None), (b'\x01a', {'source_size':MAX_CHUNK+2}, None),
            (b'\x02', {'output_size':31}, None), (b'\x00', {'state_size':STATE_BYTES-1}, None),
            (b'\x01a', {}, (1176, 0)), (b'\x01a', {}, (1104, 2)),
            (b'\x02', {}, (1096, 64)), (b'\x02', {}, (1088, MAX_TOTAL+1))):
            with self.subTest(wire=wire, kwargs=kwargs, changed=changed):
                state = ctypes.create_string_buffer(initial + b'\x5a' * 8, STATE_BYTES+8)
                if changed: struct.pack_into('<Q', state, *changed)
                before = state.raw
                code, output = self.raw(wire, state, **kwargs)
                self.assertEqual(code, 0xfffffffd)
                self.assertEqual(output, b'\xa5' * 40)
                self.assertEqual(state.raw, before)
        state = ctypes.create_string_buffer(initial + b'\x5a' * 8, STATE_BYTES+8)
        struct.pack_into('<QQ', state, 1088, MAX_TOTAL, 63)
        before = state.raw
        self.assertEqual(self.raw(b'\x01x', state)[0], 0xfffffffd)
        self.assertEqual(state.raw, before)
        self.assertEqual(self.raw(b'\x02', state)[0], 32)
        self.assertEqual(state.raw[-8:], b'\x5a' * 8)
        finalized = state.raw
        self.assertEqual(self.raw(b'\x02', state)[0], 0xfffffffd)
        self.assertEqual(state.raw, finalized)

    def test_manifest_identity_fail_closed_and_original_Core_semantics(self):
        from hepta.hia_sha256_native import payload_sha256
        from hepta.hia_program import verify_program
        from tests.test_hia_program_tools import scalar_program
        hasher = installed_stream_hasher(str(self.manifest))
        self.assertEqual(hasher.digest(b'abc').hex(), VECTORS[1][1])
        checked = verify_program(scalar_program())
        expected = sha256(checked.canonical_bytes).hexdigest()
        with patch.dict('os.environ', {'HEPTA_HIA_SHA256_STREAM_MANIFEST': str(self.manifest)}):
            with patch('hepta.hia_sha256_native._foreign_sha256', side_effect=AssertionError('foreign payload hash')):
                self.assertEqual(checked.sha256, expected)
                self.assertEqual(checked.input_sha256, expected)
            invalid = scalar_program()
            invalid['functions'][0]['blocks'][0]['term']['values'] = ['missing']
            with self.assertRaises(ValueError): verify_program(invalid)
        with patch.dict('os.environ', {'HEPTA_HIA_SHA256_STREAM_MANIFEST': '/missing/manifest'}):
            with self.assertRaises(FileNotFoundError): payload_sha256(b'abc')
        state = hasher.new(b'abc'); before = state._state.raw
        with self.assertRaises(TypeError): state.update(bytearray(b'x'))
        self.assertEqual(state._state.raw, before)
        bad = self.manifest.with_name('wrong-source.hepta'); bad.write_bytes(b'changed')
        with patch('hepta.hia_sha256_stream_native.SOURCE', bad), self.assertRaisesRegex(ValueError, 'source identity'):
            installed_stream_hasher(str(self.manifest))
