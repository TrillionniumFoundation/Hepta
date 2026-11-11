"""Independent VM, real compiler/image and exact ObjectToken protocol controls."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import ctypes
from hashlib import sha256
import json
import mmap
import os
from pathlib import Path
import random
import struct
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_composite_function_tokens import ObjectTokenDecoder, TokenProtocolError, detached_packet_index
from hepta.hia_instruction_policy_native import transport
from hepta.hia_nominal_tokens_native import (
    HEADER, REQUEST_MAGIC, REPLY_MAGIC, SCHEMA, SOURCE,
    NativeNominalTokens, NominalTokensProtocolError, installed_nominal_tokens,
)
from tools.build_hia_nominal_tokens import admit_compile_receipt

ROOT = Path(__file__).resolve().parents[1]
STREAM_MAGIC = int.from_bytes(b'HIACTK01', 'little')
COLD_REPORT = 'HEPTA_HIA_NOMINAL_TOKENS_COLD_REPORT'
EVIDENCE = 'HEPTA_HIA_NOMINAL_TOKENS_EVIDENCE'


def token(kind, value=0):
    return struct.pack('<2Q', kind, value)


def text_token(text):
    raw = text.encode('utf-8')
    return token(1, len(raw)) + raw


def tokens(value):
    typ = type(value)
    if value is None:
        return [token(4)]
    if typ is bool:
        return [token(3, int(value))]
    if typ is int:
        return [token(2, value)]
    if typ is str:
        return [text_token(value)]
    if typ is list:
        return [token(5, len(value))] + [part for item in value for part in tokens(item)]
    if typ is dict:
        return [token(6, len(value))] + [part for key, item in value.items()
                                      for part in [text_token(key), *tokens(item)]]
    raise AssertionError(typ)


def frame(payload, *, sequence=0, final=True, magic=STREAM_MAGIC, action=0,
          serial=0, slots=0, request=0):
    return HEADER.pack(magic, action, sequence, int(final), serial, slots, request, len(payload)) + payload


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')


def vm_observe(source_wire, payload, *, final=True, observed=240):
    """The checked interpreter runs begin/feed/canonical against one arena."""
    from tools.hia_selfhost_bulk import Body
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import execute_program
    body = Body(0)
    owner_w = body.value('buffer', 'buffer.new', [body.const('usize', 65536)])
    owner_o = body.value('buffer', 'buffer.new', [body.const('usize', 65536)])
    workspace = body.value('mutbuf', 'borrow.mut', [owner_w])
    output = body.value('mutbuf', 'borrow.mut', [owner_o])
    requests = [HEADER.pack(REQUEST_MAGIC, 1, STREAM_MAGIC, 0, 0, 0, 0, len(source_wire)) + source_wire,
                HEADER.pack(REQUEST_MAGIC, 2, 0, 0, 0, 0, 0, 64 + len(payload)) + frame(payload, final=final),
                HEADER.pack(REQUEST_MAGIC, 3, 0, 0, 0, 0, 0, 0)]
    results = []
    for wire in requests:
        owner = body.value('buffer', 'buffer.new', [body.const('usize', len(wire))])
        view = body.value('mutbuf', 'borrow.mut', [owner])
        for offset, byte in enumerate(wire):
            if byte:
                body.effect('buffer.store', [view, body.const('usize', offset), body.const('u8', byte)])
        body.effect('loan.end', [view])
        view = body.value('readbuf', 'borrow.read', [owner])
        results.append(body.value('u32', 'call', [view, output, workspace], {'function': 'f0'}))
        body.effect('loan.end', [view])
        body.effect('owner.drop', [owner])
    values = [body.value('u8', 'buffer.load', [output, body.const('usize', n)]) for n in range(observed)]
    body.effect('loan.end', [workspace]); body.effect('loan.end', [output])
    body.effect('owner.drop', [owner_w]); body.effect('owner.drop', [owner_o])
    source = ('hia-asm.v1 hepta.hia.program.v8 token_vm_reference\n'
              'fn observe() -> (' + ','.join(['u32'] * len(results) + ['u8'] * observed)
              + ') effects(alloc,read,write,trap) entry(b0)\nblock b0()\n'
              + body.text() + '  ret(' + ','.join([*results, *values]) + ')\nend\n'
              + SOURCE.read_text().split('\n', 1)[1])
    result = execute_program(assemble_program(source), 'observe', [], max_steps=8000000)
    if result['status'] != 'returned':
        raise AssertionError(result)
    return result['values'][:3], bytes(result['values'][3:])


class NominalTokensSourceTests(unittest.TestCase):
    def test_generated_complete_source_and_native_parameter_profile(self):
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        from tools.generate_hia_nominal_tokens import document
        self.assertEqual(SOURCE.read_text(), render_assembly(document()))
        program = assemble_program(SOURCE.read_bytes()).as_dict()
        for function in program['functions']:
            self.assertLessEqual(len(function['params']), 16)
            for block in function['blocks']:
                self.assertLessEqual(len(block['params']), 16)

    def test_independent_vm_typed_reference_canonical_and_permanent_refusal(self):
        value = {'z': [True, False, None, -123, '\x00é😀'], 'a': {'b': 9}}
        expected = canonical(value)
        codes, raw = vm_observe(transport(value), token(0, 0), observed=64 + len(expected))
        self.assertEqual(codes, [64, 64, 64])
        self.assertEqual(HEADER.unpack_from(raw)[:3], (REPLY_MAGIC, 0, 1))
        self.assertEqual(raw[64:], expected)
        codes, raw = vm_observe(transport(value), token(0, 17), observed=64)
        self.assertEqual(codes, [64, 64, 64])
        self.assertEqual(HEADER.unpack_from(raw)[1], 3)


class NominalTokensNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        expected = canonical({'a': True})
        codes, raw = vm_observe(transport({'a': True}), token(0, 0), observed=64 + len(expected))
        assert codes == [64, 64, 64] and raw[64:] == expected
        selected = os.environ.get(EVIDENCE)
        cls.temporary = None
        if selected:
            cls.folder = Path(selected).resolve()
            cls.folder.mkdir(mode=0o700)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-nominal-tokens-')
            cls.folder = Path(cls.temporary.name)
        from tools.qualify_hia_selfhost import build_seed, compile_stage
        cold = os.environ.get(COLD_REPORT)
        if cold:
            from tools.build_hia_nominal_tokens import build
            report = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(report['nested_report']).read_bytes())
            cls.compiler = Path(nested['generations'][-1]['produced_image'])
            cls.manifest = build(cls.folder / 'cold-built', cls.compiler, Path(cold))
            cls.scope = 'MATCHING_SOURCE_COLD'
            built = json.loads((cls.manifest.parent / 'build.json').read_bytes())
            cls.receipt = built['native_compile_receipt']
        else:
            seed, _ = build_seed(cls.folder)
            compiler_source = (ROOT / 'examples/hia_bootstrap/selfhost.hepta').read_bytes()
            first, _ = compile_stage(cls.folder, 'B1', seed, compiler_source, image_format='seed-shared')
            cls.compiler, _ = compile_stage(cls.folder, 'B2', first, compiler_source)
            assert first.read_bytes() == cls.compiler.read_bytes()
            image, cls.receipt = compile_stage(cls.folder, 'nominal-tokens', cls.compiler, SOURCE.read_bytes())
            cls.manifest = cls.folder / 'manifest.json'
            cls.manifest.write_text(json.dumps({'schema': SCHEMA,
                'source_sha256': sha256(SOURCE.read_bytes()).hexdigest(), 'image_path': image.name,
                'image_sha256': sha256(image.read_bytes()).hexdigest(),
                'compiler_sha256': sha256(cls.compiler.read_bytes()).hexdigest()}, sort_keys=True) + '\n')
            cls.scope = 'BOOTSTRAP_DEVELOPMENT_ONLY'
        manifest = json.loads(cls.manifest.read_bytes())
        cls.image_path = cls.manifest.parent / manifest['image_path']
        cls.image = cls.image_path.read_bytes()
        cls.compiler_bytes = cls.compiler.read_bytes()
        cls.source_bytes = SOURCE.read_bytes()
        admit_compile_receipt(cls.receipt, compiler_bytes=cls.compiler_bytes,
                              source_bytes=cls.source_bytes, image_bytes=cls.image)
        cls.native = installed_nominal_tokens(cls.manifest)
        cls.observations = []
        cls.pins = {'source_sha256': sha256(cls.source_bytes).hexdigest(),
                    'compiler_sha256': sha256(cls.compiler_bytes).hexdigest(),
                    'image_sha256': sha256(cls.image).hexdigest(),
                    'manifest_sha256': sha256(cls.manifest.read_bytes()).hexdigest(),
                    'source_files': {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in (
                        'tools/generate_hia_nominal_tokens.py', 'tools/build_hia_nominal_tokens.py',
                        'hepta/hia_nominal_tokens_native.py', 'tests/test_hia_nominal_tokens_native.py',
                        'tools/generate_hia_json_canonical.py',
                        'hepta/hia_composite_function_tokens.py')}}
        print(json.dumps({'nominal_tokens_fixture_scope': cls.scope, **cls.pins}, sort_keys=True))

    @classmethod
    def tearDownClass(cls):
        assert SOURCE.read_bytes() == cls.source_bytes
        assert cls.compiler.read_bytes() == cls.compiler_bytes
        assert cls.image_path.read_bytes() == cls.image
        (cls.folder / 'observations.json').write_text(json.dumps({
            'schema': 'hepta.hia.nominal-tokens-observations.v1',
            'status': 'OBSERVATIONS_RECORDED_SEE_TEST_RUNNER_RESULT', 'scope': cls.scope,
            'pins': cls.pins, 'native_compile_receipt': cls.receipt, 'observations': cls.observations,
            'public_route_changed': False, 'whole_stack_rewritten_in_hia': False}, sort_keys=True, indent=2) + '\n')
        if cls.temporary:
            cls.temporary.cleanup()

    def render(self, source, chunks, *, identity=(STREAM_MAGIC, 0, 0, 0, 0)):
        wire = transport(source)
        _, index = detached_packet_index(wire)
        reference = ObjectTokenDecoder(index)
        magic, action, serial, slots, request = identity
        with self.native.session() as session:
            session.begin(wire, magic, action, serial=serial, slots=slots, request=request)
            for n, payload in enumerate(chunks):
                final = n == len(chunks) - 1
                reference.feed(payload, final=final)
                complete = session.feed(frame(payload, sequence=n, final=final,
                    magic=magic, action=action, serial=serial, slots=slots, request=request))
                self.assertEqual(complete, final)
            actual = session.canonical()
            expected = canonical(reference.root)
            self.assertEqual(actual, expected)
            self.assertEqual(session.canonical(), actual)
            self.observations.append({'source_sha256': sha256(wire).hexdigest(),
                'tokens_sha256': sha256(b''.join(chunks)).hexdigest(), 'chunks': len(chunks),
                'token_count': session.token_count, 'output_bytes': len(actual),
                'output_sha256': sha256(actual).hexdigest()})
            return actual

    def test_scalar_types_arbitrary_integer_lexemes_and_unicode(self):
        values = [None, False, True, 0, -1, 2**513, -(2**513), '', [], {},
                  {'z': ['\x00\b\t\n\f\r\\"/', False], 'é😀': [1, True, None]}]
        values += [chr(cp) for cp in (0, 31, 32, 127, 128, 2047, 2048, 55295, 57344, 65535, 65536, 1114111)]
        for value in values:
            with self.subTest(value=repr(value)[:100]):
                self.render(value, [token(0, 0)])
        for value in (0, 1, 9, 10, 99, 100, 2**32, 2**63, 2**64-1):
            self.render(None, [token(2, value)])
        raw = b'-' + b'9' * 8000
        wire = token(2, len(raw)) + raw
        with self.native.session() as session:
            session.begin(wire, STREAM_MAGIC, 0)
            session.feed(frame(token(0, 0)))
            self.assertEqual(session.canonical(), raw)

    def test_every_actual_source_node_and_key_boundary(self):
        value = {'z': [None, False, -17, {'é': 'payload with fake header\x00'}], 'a': [1, 2]}
        wire = transport(value)
        _, index = detached_packet_index(wire)
        for offset, item in index.items():
            with self.subTest(offset=offset):
                self.assertEqual(self.render(value, [token(0, offset)]), canonical(item))
        for offset in range(len(wire)):
            if offset in index:
                continue
            with self.native.session() as session:
                session.begin(wire, STREAM_MAGIC, 0)
                with self.assertRaises(NominalTokensProtocolError):
                    session.feed(frame(token(0, offset)))

    def test_cross_frame_containers_and_three_owner_identities(self):
        value = {'z': [1, {'t': [None, False, True]}], 'a': 'é😀\u0000'}
        pieces = tokens(value)
        for magic in (b'HIACTK01', b'HIAFNC01', b'HIAOTK01'):
            for stride in (1, 2, 5, len(pieces)):
                chunks = [b''.join(pieces[i:i+stride]) for i in range(0, len(pieces), stride)]
                self.render(None, chunks, identity=(int.from_bytes(magic, 'little'), 5, 97, 129, 11))
        self.render(None, [token(5, 0), b''])

    def test_one_thousand_random_trees_and_chunk_cuts(self):
        rng = random.Random(742068)
        def tree(depth=0):
            if depth < 5 and rng.randrange(3):
                if rng.randrange(2):
                    return [tree(depth+1) for _ in range(rng.randrange(5))]
                return {f'k{n}é': tree(depth+1) for n in reversed(range(rng.randrange(5)))}
            return rng.choice([None, True, False, rng.randrange(1 << 64), 'é😀\x00\\"'])
        for _ in range(1000):
            value = tree()
            pieces = tokens(value)
            stride = rng.randrange(1, 17)
            self.render(value, [b''.join(pieces[i:i+stride]) for i in range(0, len(pieces), stride)])

    def test_malformed_source_packet_domain(self):
        bad = [b'', b'x', token(0, 1) + b'x', token(1, 0), token(1, 1) + b'\x02',
               token(2, 0), token(2, 2) + b'-0', token(2, 2) + b'01', token(2, 2) + b'+1',
               token(3, 1) + b'0', token(4, 3) + b'\xed\xa0\x80', token(4, 2) + b'\xc0\x80',
               token(4, 4) + b'\xf4\x90\x80\x80', token(4, 2) + b'\xe2\x82',
               token(5, 8) + struct.pack('<Q', 1), token(6, 8) + struct.pack('<Q', 1),
               token(0) + token(0), token(7)]
        duplicate = struct.pack('<Q', 2) + transport('a') + transport(0) + transport('a') + transport(1)
        bad.append(token(6, len(duplicate)) + duplicate)
        non_string_key = struct.pack('<Q', 1) + transport(1) + transport(None)
        bad.append(token(6, len(non_string_key)) + non_string_key)
        for wire in bad:
            with self.subTest(wire=wire[:80]), self.native.session() as session:
                with self.assertRaises(NominalTokensProtocolError):
                    session.begin(wire, STREAM_MAGIC, 0)
                with self.assertRaises(NominalTokensProtocolError):
                    session.begin(transport(None), STREAM_MAGIC, 0)

    def test_malformed_tokens_and_permanent_poison(self):
        bad = [b'x', token(7), token(3, 2), token(4, 1), token(0, 1),
               token(1, 2)+b'x', token(1, 3)+b'\xed\xa0\x80', token(1, 2)+b'\xc0\x80',
               token(5, 1), token(6, 1), token(4)+token(4),
               token(6, 1)+token(2, 3)+token(4),
               token(6, 2)+text_token('a')+token(4)+text_token('a')+token(4),
               token(5, (1 << 64)-1), token(6, (1 << 64)-1)]
        for payload in bad:
            with self.subTest(payload=payload[:80]), self.native.session() as session:
                session.begin(transport(None), STREAM_MAGIC, 0)
                with self.assertRaises(NominalTokensProtocolError):
                    session.feed(frame(payload))
                for call in (session.canonical, lambda: session.feed(frame(token(4))),
                             lambda: session.restart(STREAM_MAGIC, 0)):
                    with self.assertRaises(NominalTokensProtocolError):
                        call()

    def test_duplicate_source_reference_keys_fail_on_the_duplicate_frame(self):
        wire = transport({'same': 1})
        _, index = detached_packet_index(wire)
        key = next(offset for offset, value in index.items() if value == 'same')
        with self.native.session() as session:
            session.begin(wire, STREAM_MAGIC, 0)
            self.assertFalse(session.feed(frame(token(6, 2)+token(0, key)+token(4), final=False)))
            with self.assertRaises(NominalTokensProtocolError):
                session.feed(frame(text_token('same'), sequence=1, final=False))

    def test_every_stream_identity_word_extent_sequence_and_terminal_state(self):
        good = frame(token(4), action=3, serial=4, slots=5, request=6)
        for index in range(8):
            bad = bytearray(good)
            value = struct.unpack_from('<Q', bad, index*8)[0]
            struct.pack_into('<Q', bad, index*8, value + 1)
            with self.native.session() as session:
                session.begin(transport(None), STREAM_MAGIC, 3, serial=4, slots=5, request=6)
                with self.assertRaises(NominalTokensProtocolError):
                    session.feed(bytes(bad))
        for bad in (good[:63], good[:-1], good+b'x'):
            with self.native.session() as session:
                session.begin(transport(None), STREAM_MAGIC, 3, serial=4, slots=5, request=6)
                with self.assertRaises(NominalTokensProtocolError):
                    session.feed(bad)
        with self.native.session() as session:
            session.begin(transport(None), STREAM_MAGIC, 0)
            session.feed(frame(token(4)))
            with self.assertRaises(NominalTokensProtocolError):
                session.feed(frame(b'', sequence=1))

    def test_retained_dictionary_handles_restart_and_namespace_refusals(self):
        handle = 1 << 63
        with self.native.session() as session:
            session.begin(transport({'source': -7}), STREAM_MAGIC, 0)
            session.feed(frame(token(0, 0)))
            session.seal(handle)
            session.restart(STREAM_MAGIC, 5, request=1)
            session.feed(frame(token(6, 2)+text_token('z')+token(0, handle)
                               +text_token('a')+token(0, 0), action=5, request=1))
            self.assertEqual(session.canonical(), b'{"a":{"source":-7},"z":{"source":-7}}')
            session.seal((1 << 64)-1)
            session.restart(STREAM_MAGIC, 0, request=2)
            session.feed(frame(token(0, (1 << 64)-1), request=2))
            self.assertEqual(session.canonical(), b'{"a":{"source":-7},"z":{"source":-7}}')
        for source, target in ((None, handle), ({}, handle-1)):
            with self.native.session() as session:
                session.begin(transport(source), STREAM_MAGIC, 0)
                session.feed(frame(token(0, 0)))
                with self.assertRaises(NominalTokensProtocolError):
                    session.seal(target)
        with self.native.session() as session:
            session.begin(transport({}), STREAM_MAGIC, 0)
            session.feed(frame(token(0, 0)))
            session.seal(handle)
            with self.assertRaises(NominalTokensProtocolError):
                session.seal(handle)
        with self.native.session() as session:
            session.begin(transport({}), STREAM_MAGIC, 0)
            with self.assertRaises(NominalTokensProtocolError):
                session.feed(frame(token(0, handle)))

    def test_workspace_growth_no_new_expanded_output_quota_and_reclaim(self):
        value = 'é😀' * 150000
        wire = transport(value)
        payload = token(5, 16) + token(0, 0) * 16
        with self.native.session() as session:
            session.begin(wire, STREAM_MAGIC, 0)
            session.feed(frame(payload))
            actual = session.canonical()
            self.assertGreater(len(actual), 8 << 20)
            self.assertEqual(actual, canonical([value]*16))
            retained = struct.unpack_from('<Q', session._workspace, 112)[0]
            for request in range(1, 17):
                session.restart(STREAM_MAGIC, 0, request=request)
                session.feed(frame(token(4), request=request))
                self.assertEqual(session.canonical(), b'null')
                self.assertLessEqual(struct.unpack_from('<Q', session._workspace, 16)[0], retained + 128)

    def test_direct_capacity_retries_do_not_consume_or_publish(self):
        wire = transport({'key': 'v'*100})
        request = HEADER.pack(REQUEST_MAGIC, 1, STREAM_MAGIC, 0, 0, 0, 0, len(wire)) + wire
        source = ctypes.create_string_buffer(request)
        output = ctypes.create_string_buffer(b'\xa5'*512)
        workspace = ctypes.create_string_buffer(512)
        before = output.raw[64:512]
        self.assertEqual(self.native._entry(source, len(request), output, 512, workspace, 512), 64)
        reply = HEADER.unpack_from(output)
        self.assertEqual(reply[1], 1)
        self.assertEqual(reply[3], 0)
        self.assertGreater(reply[4], 512)
        self.assertEqual(output.raw[64:512], before)
        self.assertEqual(struct.unpack_from('<Q', workspace)[0], 0)
        with self.native.session() as session:
            session.begin(wire, STREAM_MAGIC, 0)
            session.feed(frame(token(0, 0)))
            request = HEADER.pack(REQUEST_MAGIC, 3, 0, 0, 0, 0, 0, 0)
            source = ctypes.create_string_buffer(request)
            address = ctypes.addressof(ctypes.c_char.from_buffer(session._workspace))
            self.assertEqual(self.native._entry(source, 64, output, 64, address, len(session._workspace)), 64)
            reply = HEADER.unpack_from(output)
            self.assertEqual(reply[1], 2)
            self.assertEqual(reply[3], 1)
            self.assertEqual(output.raw[64:512], before)
            self.assertEqual(session.canonical(), canonical({'key': 'v'*100}))

    def test_native_return_full_abi_input_custody_and_mapping_cleanup(self):
        entry = self.native._entry
        def high_bits(*args):
            return entry(*args) + (1 << 32)
        session = self.native.session()
        mappings = (session._workspace, session._output)
        try:
            with patch.object(self.native, '_entry', high_bits):
                with self.assertRaises(NominalTokensProtocolError):
                    session.begin(transport(None), STREAM_MAGIC, 0)
        finally:
            session.close()
        self.assertTrue(all(mapping.closed for mapping in mappings))
        def changed_input(*args):
            result = entry(*args)
            ctypes.memset(args[0], 0, 1)
            return result
        with self.native.session() as session, patch.object(self.native, '_entry', changed_input):
            with self.assertRaises(NominalTokensProtocolError):
                session.begin(transport(None), STREAM_MAGIC, 0)

    def test_payload_independence_and_concurrent_private_sessions(self):
        wire = transport({'z': [1, False], 'a': 'é'})
        expected = b'{"a":"\xc3\xa9","z":[1,false]}'
        def invoke(_):
            with self.native.session() as session:
                session.begin(wire, STREAM_MAGIC, 0)
                session.feed(frame(token(0, 0)))
                return session.canonical()
        with (patch('json.loads', side_effect=AssertionError('host JSON payload decoder')),
              patch('json.dumps', side_effect=AssertionError('host JSON payload encoder'))):
            with (patch('hepta.hia_composite_function_tokens.ObjectTokenDecoder', side_effect=AssertionError('host object materialization')),
                  patch('hepta.hia_instruction_policy_native.transport', side_effect=AssertionError('host typed payload encoder'))):
                self.assertEqual(invoke(0), expected)
        with ThreadPoolExecutor(max_workers=4) as pool:
            self.assertEqual(list(pool.map(invoke, range(16))), [expected]*16)

    def test_compile_receipt_binds_actual_compiler_and_all_numeric_fields(self):
        for field, value in [('artifact_sha256', '0'*64), ('image_sha256', '0'*64),
                ('status', 'failed'), ('source_unchanged', 1), ('forbidden_compiler_modules_loaded', ['x']),
                ('input_sha256', '0'*64), ('produced_sha256', '0'*64),
                ('core_u32', True), ('result_u64', len(self.image)+(1 << 32)),
                ('input_bytes', len(self.source_bytes)+1), ('produced_bytes', len(self.image)+1)]:
            bad = dict(self.receipt); bad[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                admit_compile_receipt(bad, compiler_bytes=self.compiler_bytes,
                                      source_bytes=self.source_bytes, image_bytes=self.image)


if __name__ == '__main__':
    unittest.main()
