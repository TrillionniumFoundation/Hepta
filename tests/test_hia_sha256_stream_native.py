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


# The reference is the exact ac3 byte-loop assembly, not a newly chosen digest
# implementation. It is rebuilt only by the Native tests. Source controls use
# the ordinary Core VM and require neither a seed nor a native compiler.
RETAINED_STREAM_ASSEMBLY_SHA256 = '7fdc436867514b3d1dd741e3c3d86c0b95cc19d5b69907d5df9febf29639cb68'


def retained_loop_source():
    from tools.generate_hia_sha256_stream import source_program, STREAM_WORD_HELPERS
    from tools.generate_hia_sha256 import HELPERS
    source = source_program()
    assert source.count(STREAM_WORD_HELPERS) == 1
    return source.replace(STREAM_WORD_HELPERS, HELPERS[HELPERS.index('\ndef get'):])


def retained_loop_assembly():
    from hepta.hia_agent_assembly import render_assembly
    from tools.generate_hia_sha256_stream import retained_loop_document as word_document
    wire = render_assembly(word_document(retained_loop_source(), 'sha256_stream')).encode()
    assert sha256(wire).hexdigest() == RETAINED_STREAM_ASSEMBLY_SHA256
    return wire


def vm_word_access(helpers, offset, value):
    from tools.hia_selfhost_bulk import Body
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    from hepta.hia_program import execute_program
    from tools.generate_hia_artifact_publication import document as word_document
    program = ('def probe(w:mutbuf, index:u64, value:u64) -> u64:\n'
               '    put(w, index, value)\n'
               '    return get(w, index)\n' + helpers)
    fragment = render_assembly(word_document(program, 'word_access')).split('\n', 1)[1]
    body = Body(0)
    owner = body.value('buffer', 'buffer.new', [body.const('usize', 24)])
    view = body.value('mutbuf', 'borrow.mut', [owner])
    for index in range(24):
        body.effect('buffer.store', [view, body.const('usize', index), body.const('u8', 0xa5)])
    result = body.value('u64', 'call',
                        [view, body.const('u64', offset), body.const('u64', value)],
                        {'function': 'f0'})
    observed = [body.value('u8', 'buffer.load', [view, body.const('usize', index)])
                for index in range(24)]
    body.effect('loan.end', [view])
    body.effect('owner.drop', [owner])
    source = ('hia-asm.v1 hepta.hia.program.v8 word_reference\n'
              'fn observe() -> (' + ','.join(['u64'] + ['u8'] * 24)
              + ') effects(alloc,read,write,trap) entry(b0)\nblock b0()\n'
              + body.text() + '  ret(' + ','.join([result, *observed])
              + ')\nend\n' + fragment)
    observation = execute_program(assemble_program(source), 'observe', [], max_steps=100000)
    assert observation['status'] == 'returned', observation
    return observation['values'][0], bytes(observation['values'][1:])



class Sha256StreamSourceTests(unittest.TestCase):
    def test_generated_source_and_independent_VM_chunk_transitions(self):
        from hepta.hia_agent_assembly import render_assembly
        self.assertEqual(SOURCE.read_text(), render_assembly(document()))
        for chunks in ([], [b'a', b'', b'bc'], [b'a' * 55, b'b'], [b'a' * 63, b'b', b'c']):
            self.assertEqual(vm_stream(chunks), sha256(b''.join(chunks)).digest())


    def test_stream_only_word_access_retains_full_width_order_and_neighbour_bytes(self):
        import ast
        from tools.generate_hia_sha256 import HELPERS
        from tools.generate_hia_sha256_stream import STREAM_WORD_HELPERS
        original = HELPERS[HELPERS.index('\ndef get'):]
        self.assertTrue(any(isinstance(node, ast.While) for node in ast.walk(ast.parse(original))))
        self.assertFalse(any(isinstance(node, ast.While)
                             for node in ast.walk(ast.parse(STREAM_WORD_HELPERS))))
        # This hash is the previously published complete stream source. Its
        # compression/padding/entry guards remain exactly the reference here.
        self.assertEqual(sha256(retained_loop_assembly()).hexdigest(),
                         RETAINED_STREAM_ASSEMBLY_SHA256)
        for offset, value in ((0, 0), (1, 1), (3, 0x0102030405060708),
                              (8, 0xffffffffffffffff), (15, 0x8000000000000001),
                              (16, 0xff00ff00ff00ff00)):
            with self.subTest(offset=offset, value=value):
                expected = bytearray(b'\xa5' * 24)
                expected[offset:offset + 8] = value.to_bytes(8, 'little')
                wanted = (value, bytes(expected))
                self.assertEqual(vm_word_access(original, offset, value), wanted)
                self.assertEqual(vm_word_access(STREAM_WORD_HELPERS, offset, value), wanted)


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
        cls.folder, cls.compiler = folder, second
        cls._loop_image = None
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


    def _retained_loop_image(self):
        cls = type(self)
        if cls._loop_image is None:
            from tools.qualify_hia_selfhost import compile_stage
            wire = retained_loop_assembly()
            image, receipt = compile_stage(cls.folder, 'sha256-stream-ac3-byte-loops',
                                           cls.compiler, wire)
            raw = image.read_bytes()
            cls._loop_image = NativeSha256Stream(raw, sha256(raw).hexdigest())
            cls._loop_receipt = receipt
        return cls._loop_image

    def _complete_raw_observation(self, image, wire, state_bytes, *,
                                  output_size=32, state_size=STATE_BYTES,
                                  source_size=None):
        source = ctypes.create_string_buffer(wire + b'\x3c' * 8, len(wire) + 8)
        state = ctypes.create_string_buffer(state_bytes + b'\x5a' * 8, STATE_BYTES + 8)
        output = ctypes.create_string_buffer(b'\xa5' * 40, 40)
        source_before = source.raw
        code = image._entry(source, len(wire) if source_size is None else source_size,
                            output, output_size, state, state_size)
        self.assertEqual(source.raw, source_before)
        self.assertEqual(state.raw[STATE_BYTES:], b'\x5a' * 8)
        self.assertEqual(output.raw[32:], b'\xa5' * 8)
        return code, output.raw, state.raw

    def test_every_native_transition_matches_retained_complete_state_and_output(self):
        original = self._retained_loop_image()
        for fill in (0, 0xa5, 0xff):
            states = [bytes([fill]) * STATE_BYTES] * 2
            payload = b''
            wires = [b'\x00', b'\x01', b'\x01a', b'\x01' + b'b' * 54,
                     b'\x01\xff', b'\x01' + bytes(range(64)), b'\x01xyz',
                     b'\x01' + bytes(range(256)), b'\x02', b'\x02']
            for position, wire in enumerate(wires):
                with self.subTest(fill=fill, position=position):
                    observations = [
                        self._complete_raw_observation(image, wire, states[index])
                        for index, image in enumerate((original, self.image))]
                    self.assertEqual(observations[0], observations[1])
                    states = [observed[2][:STATE_BYTES] for observed in observations]
                    if wire[:1] == b'\x01':
                        payload += wire[1:]
                        self.assertEqual(observations[0][0], 0)
                        self.assertEqual(observations[0][1], b'\xa5' * 40)
                    elif position == len(wires) - 2:
                        self.assertEqual(observations[0][0], 32)
                        self.assertEqual(observations[0][1][:32], sha256(payload).digest())
                    elif position == len(wires) - 1:
                        self.assertEqual(observations[0][0], 0xfffffffd)
        for length in (55, 56, 63, 64, 65, 119, 120, 127, 128, 129):
            payload = bytes((index * 137 + 29) & 255 for index in range(length))
            states = [bytes(STATE_BYTES)] * 2
            for wire in (b'\x00', b'\x01' + payload, b'\x02'):
                observations = [
                    self._complete_raw_observation(image, wire, states[index])
                    for index, image in enumerate((original, self.image))]
                self.assertEqual(observations[0], observations[1], (length, wire[:1]))
                states = [observed[2][:STATE_BYTES] for observed in observations]
            self.assertEqual(observations[0][1][:32], sha256(payload).digest())

    def test_retained_u64_state_words_and_refusal_have_identical_side_effects(self):
        original = self._retained_loop_image()
        initial = original.new(b'abc')._state.raw
        cases = [
            (b'\x01d', (), {}),
            (b'\x02', ((0, 0x8000000000000001), (1024, 0xffffffffffffffff)), {}),
            (b'\x01d', ((1088, (1 << 40) + 3),), {}),
            (b'\x02', ((1088, (1 << 40) + 3),), {}),
            (b'\x01d', ((1176, 0),), {}),
            (b'\x01d', ((1104, 2),), {}),
            (b'\x02', ((1096, 64),), {}),
            (b'\x02', ((1088, MAX_TOTAL + 1),), {}),
            (b'\x01x', ((1088, MAX_TOTAL), (1096, 63)), {}),
            (b'\x02', (), {'output_size': 31}),
            (b'\x00', (), {'state_size': STATE_BYTES - 1}),
            (b'\x01a', (), {'source_size': MAX_CHUNK + 2}),
        ]
        for wire, mutations, options in cases:
            with self.subTest(wire=wire, mutations=mutations, options=options):
                state = bytearray(initial)
                for offset, value in mutations:
                    struct.pack_into('<Q', state, offset, value)
                observations = [
                    self._complete_raw_observation(image, wire, bytes(state), **options)
                    for image in (original, self.image)]
                self.assertEqual(observations[0], observations[1])
                if observations[0][0] == 0xfffffffd:
                    self.assertEqual(observations[0][1], b'\xa5' * 40)
                    self.assertEqual(observations[0][2], bytes(state) + b'\x5a' * 8)

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
