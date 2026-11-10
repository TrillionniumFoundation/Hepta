"""Independent VM and actual native type grammar, positions and no fallback."""
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

from hepta.ast import HeptaError, Type
from hepta.hia_source_types_native import (SOURCE, SCHEMA, WORKSPACE, NativeSourceTypes,
                                         materialize, installed_source_types)
from hepta.hia_source_lexer_native import NativeSourceLexer, SCHEMA as LEXER_SCHEMA
from hepta.parser import Parser, parse, _MAX_NESTING
ROOT = Path(__file__).resolve().parents[1]
SELECTORS = {name: '' for name in (
    'HEPTA_HIA_SOURCE_FRONTEND_MANIFEST', 'HEPTA_HIA_SOURCE_NAMES_MANIFEST',
    'HEPTA_HIA_SOURCE_EXPRESSIONS_MANIFEST', 'HEPTA_HIA_SOURCE_TYPES_MANIFEST',
    'HEPTA_HIA_SOURCE_CLAUSES_MANIFEST', 'HEPTA_HIA_SOURCE_LEXER_MANIFEST')}


def vm_window(wire, begin=0, count=128, capacity=1024, depth=128):
    from tools.hia_selfhost_bulk import Body
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import execute_program
    b = Body(0); owners = []; views = []
    state = bytearray(WORKSPACE); struct.pack_into('<Q', state, 224, depth)
    for size, initial in ((len(wire), wire), (capacity, b''), (WORKSPACE, state)):
        owner = b.value('buffer', 'buffer.new', [b.const('usize', size)])
        view = b.value('mutbuf', 'borrow.mut', [owner])
        for i, value in enumerate(initial):
            if value: b.effect('buffer.store', [view, b.const('usize', i), b.const('u8', value)])
        owners.append(owner); views.append(view)
    b.effect('loan.end', [views[0]])
    views[0] = b.value('readbuf', 'borrow.read', [owners[0]])
    code = b.value('u32', 'call', views, {'function': 'f0'})
    raw = [b.value('u8', 'buffer.load', [views[1], b.const('usize', i)])
           for i in range(begin, begin + count)]
    for view in views: b.effect('loan.end', [view])
    for owner in owners: b.effect('owner.drop', [owner])
    source = ('hia-asm.v1 hepta.hia.program.v8 source_type_reference\n'
        'fn observe() -> (u32,' + ','.join(['u8'] * count) + ') '
        'effects(alloc,read,write,trap) entry(b0)\nblock b0()\n' + b.text()
        + '  ret(' + ','.join([code, *raw]) + ')\nend\n' + SOURCE.read_text().split('\n', 1)[1])
    result = execute_program(assemble_program(source), 'observe', [], max_steps=2000000)
    assert result['status'] == 'returned', result
    code, *raw = result['values']
    return code, bytes(raw)


def vm_arena(wire):
    code, first = vm_window(wire)
    if code > 1024: return code, None
    chunks = [first]
    for begin in range(128, code, 128):
        again, chunk = vm_window(wire, begin, min(128, code - begin))
        assert again == code
        chunks.append(chunk)
    return code, b''.join(chunks)[:code]


def references():
    rows = []
    for source, expected in [('u8', Type('u8')),
        ('Buffer<u8>', Type('Buffer', (Type('u8'),))),
        ("read 'a [u8]", Type('ref_read', (Type('slice', (Type('u8'),)),), lifetimes=('a',)))]:
        code, raw = vm_arena(source.encode())
        assert code == len(raw)
        value, chars, consumed = materialize(raw, source.encode(), lambda _: (_ for _ in ()).throw(AssertionError('unexpected integer')))
        assert value == expected and chars == consumed == len(source)
        rows.append((source.encode(), raw))
    for source in (b'raw u8', b'Buffer', b'X<>', b'read u8'):
        assert vm_window(source)[0] == 0xffffffff
    return rows


def type_outcome(source, selected=None, depth=0):
    with patch.dict('os.environ', {**SELECTORS, 'HEPTA_HIA_SOURCE_TYPES_MANIFEST': selected or '',
                                 'HEPTA_HIA_SOURCE_LEXER_MANIFEST': ''}):
        try:
            parser = Parser(source, 'types.hepta'); parser.depth = depth
            value = parser._type()
            return ('type', value, parser.position, parser.tokens, parser.current, parser.previous, parser.depth)
        except HeptaError as error: return ('error', error.diagnostic.to_dict())


class SourceTypesSourceTests(unittest.TestCase):
    def test_generated_HIA_source_exact_and_independent_VM(self):
        from tools.generate_hia_source_types import document
        from hepta.hia_agent_assembly import render_assembly
        self.assertEqual(SOURCE.read_text(), render_assembly(document()))
        self.assertEqual(len(references()), 3)


class SourceTypesNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.references = references()  # Genuine independent execution before B0.
        from tools.qualify_hia_selfhost import build_seed, compile_stage
        cls.temporary = tempfile.TemporaryDirectory(prefix='hia-source-types-')
        cls.folder = Path(cls.temporary.name)
        seed, _ = build_seed(cls.folder)
        compiler = (ROOT / 'examples/hia_bootstrap/selfhost.hiaasm').read_bytes()
        first, _ = compile_stage(cls.folder, 'B1', seed, compiler, image_format='seed-shared')
        second, _ = compile_stage(cls.folder, 'B2', first, compiler)
        assert first.read_bytes() == second.read_bytes()
        image, cls.receipt = compile_stage(cls.folder, 'source-types', second, SOURCE.read_bytes())
        cls.native = NativeSourceTypes(image.read_bytes(), sha256(image.read_bytes()).hexdigest())
        cls.manifest = cls.folder / 'manifest.json'
        cls.manifest.write_text(json.dumps({'schema': SCHEMA, 'source_sha256': sha256(SOURCE.read_bytes()).hexdigest(),
            'image_path': image.name, 'image_sha256': sha256(image.read_bytes()).hexdigest(),
            'compiler_sha256': sha256(second.read_bytes()).hexdigest()}))
        lexer_source = ROOT / 'examples/hia_bootstrap/source_lexer.hiaasm'
        lexer_image, _ = compile_stage(cls.folder, 'lexer', second, lexer_source.read_bytes())
        cls.lexer = NativeSourceLexer(lexer_image.read_bytes(), sha256(lexer_image.read_bytes()).hexdigest())
        folder = cls.folder / 'source-lexer'; folder.mkdir()
        (folder / 'manifest.json').write_text(json.dumps({'schema': LEXER_SCHEMA,
            'source_sha256': sha256(lexer_source.read_bytes()).hexdigest(), 'image_path': '../' + lexer_image.name,
            'image_sha256': sha256(lexer_image.read_bytes()).hexdigest(),
            'compiler_sha256': sha256(second.read_bytes()).hexdigest()}))

    @classmethod
    def tearDownClass(cls): cls.temporary.cleanup()

    def compare(self, source, depth=0):
        self.assertEqual(type_outcome(source, str(self.manifest), depth), type_outcome(source, depth=depth), repr(source[:180]))

    def test_native_every_byte_matches_independent_VM_before_seed(self):
        for wire, raw in self.references:
            actual, _ = self.native.run(wire, max_depth=128)
            self.assertEqual(actual, raw)
        self.assertEqual(self.receipt['forbidden_compiler_modules_loaded'], [])

    def test_complete_grammar_paths_lifetimes_arrays_references_and_pointer_modes(self):
        for source in ('u8', 'pkg /* π🙂 */ :: value::Type', 'Buffer<[u8; 0x7f]>',
            "read 'a raw const pkg::Type<'b,raw mut [u64]>",
            "X<'a,u8,'b,Buffer<T>>", 'Task<Sender<Buffer<u8>>>',
            '[[[[[u8]]]]]', '[u8; 0b1_010]', '[u8; 0o777]',
            '[u8; ' + '9' * 4096 + ']', 'u8 + 2', 'X<X<T>>=0',
            'X<T>=0', 'X<T>>0', 'T >> 0', "read 'a X<'b>",
            '/* π */\r\n  X<\r\n u8\r\n>\r fn', '[u8; 0x' + 'f' * 4094 + ']'):
            with self.subTest(source=source[:80]): self.compare(source)

    def test_exact_diagnostic_messages_codes_spans_and_remaining_depth(self):
        for source in ('', '[]', '[u8', '[u8;', '[u8; -1]', '[u8; 1.0]', '[u8; 1',
            '[u8; 1 u32]', 'raw', 'raw u8', "read u8", 'mut', 'Buffer', 'Task<u8,u64>',
            'Sender<\'a>', 'X<>', 'X<u8,>', 'X<u8', 'X::', 'X::raw', 'fn',
            'X<X<T>=0', "read 'a [Buffer]", 'X<u8,raw u8>', 'X<\'a,>', '#'):
            for prefix in ('', '/* π🙂 */\r\n  '):
                with self.subTest(source=(prefix + source)[:100]): self.compare(prefix + source)
        for wrappers in (_MAX_NESTING - 2, _MAX_NESTING - 1, _MAX_NESTING, _MAX_NESTING + 1):
            self.compare('[' * wrappers + 'T' + ']' * wrappers)
        for depth in (1, 40, _MAX_NESTING - 1, _MAX_NESTING):
            self.compare('[[u8]]', depth)

    def test_native_explicit_frame_boundary_does_not_use_host_recursion(self):
        for wrappers, valid in ((127, True), (128, False)):
            wire = ('[' * wrappers + 'T' + ']' * wrappers).encode()
            raw, state = self.native.run(wire, max_depth=128)
            if valid:
                value, characters, consumed = materialize(raw, wire, self.lexer.integer_value)
                self.assertEqual(characters, len(wire)); self.assertEqual(consumed, len(wire))
                for _ in range(wrappers):
                    self.assertEqual(value.name, 'slice'); value = value.args[0]
                self.assertEqual(value, Type('T'))
            else:
                self.assertIsNone(raw); self.assertEqual(struct.unpack_from('<Q', state, 216)[0], 1)

    def test_deterministic_mixed_valid_and_invalid_grammar(self):
        rng = random.Random(0x7a9e2026)
        def make(depth):
            if depth == 0: return rng.choice(['u8', 'pkg::Name', 'T', 'raw const i64'])
            child = make(depth - 1)
            return rng.choice(['[' + child + ']', '[' + child + '; 0xff]',
                'Buffer<' + child + '>', "read 'life " + child, "X<'a," + child + ",'b,u64>",
                'raw mut ' + child])
        for _ in range(250):
            source = make(rng.randrange(0, 7)); self.compare(source)
            self.compare(source[:rng.randrange(len(source) + 1)])

    def test_all_actual_repository_sources_and_default_parser_have_equal_AST(self):
        paths = sorted((ROOT / 'tests').rglob('*.hepta')) + sorted((ROOT / 'examples').rglob('*.hepta'))
        self.assertGreater(len(paths), 0)
        print(f'native types corpus files: {len(paths)}')
        for path in paths:
            source = path.read_text()
            def call(manifest):
                with patch.dict('os.environ', {**SELECTORS, 'HEPTA_HIA_SOURCE_TYPES_MANIFEST': manifest,
                                             'HEPTA_HIA_SOURCE_LEXER_MANIFEST': ''}):
                    try: return ('tree', parse(source, str(path)))
                    except HeptaError as error: return ('error', error.diagnostic.to_dict())
            with self.subTest(path=str(path)): self.assertEqual(call(str(self.manifest)), call(''))

    def test_real_declaration_expression_cast_and_concurrent_callers_no_host_grammar(self):
        source = "module demo; struct Pair<'a,T> { x: read 'a T, y: [u64;0xff] } fn f(x: u64) -> u64 effects{} { let y: u64 = x as u64; return y; }"
        with patch.dict('os.environ', {**SELECTORS, 'HEPTA_HIA_SOURCE_TYPES_MANIFEST': ''}): expected = parse(source)
        with patch.dict('os.environ', {**SELECTORS, 'HEPTA_HIA_SOURCE_TYPES_MANIFEST': str(self.manifest)}), \
             patch.object(Parser, '_reference_type', side_effect=AssertionError('foreign type grammar')), \
             patch('hepta.lexer.Lexer.tokenize', side_effect=AssertionError('foreign lexer')):
            with ThreadPoolExecutor(max_workers=8) as pool:
                self.assertEqual(list(pool.map(parse, [source] * 32)), [expected] * 32)

    def test_transactional_refusal_and_poisoned_workspace_guards(self):
        for wire, capacity, state_size, depth, wanted in ((b'T', 1, WORKSPACE, 128, 0xfffffffe),
            (b'T', 512, WORKSPACE - 1, 128, 0xfffffffd), (b'T', 512, WORKSPACE, 0, 0xfffffffd),
            (b'T', 512, WORKSPACE, 129, 0xfffffffd), (b'Buffer', 512, WORKSPACE, 128, 0xffffffff),
            (b'[[T]]', 512, WORKSPACE, 2, 0xffffffff), (b'T::', 512, WORKSPACE, 128, 0xffffffff),
            (b'/*\xc0\x80*/', 512, WORKSPACE, 128, 0xffffffff)):
            source = ctypes.create_string_buffer(wire, len(wire))
            output = ctypes.create_string_buffer(b'\xa5' * (capacity + 8), capacity + 8)
            state = ctypes.create_string_buffer(b'\x5a' * (state_size + 8), state_size + 8)
            struct.pack_into('<Q', state, 224, depth)
            result = self.native._entry(source, len(wire), output, capacity, state, state_size)
            self.assertEqual(result, wanted)
            self.assertEqual(output.raw, b'\xa5' * (capacity + 8))
            self.assertEqual(state.raw[state_size:], b'\x5a' * 8)
            self.assertEqual(source.raw, wire)

    def test_arena_rejects_cycles_orphans_aliases_bad_ranges_and_wrong_kinds(self):
        wire = b"read 'a Buffer<u8>"; raw, _ = self.native.run(wire, max_depth=128)
        self.assertEqual(materialize(raw, wire, self.lexer.integer_value)[0], Type('ref_read',
            (Type('Buffer', (Type('u8'),)),), lifetimes=('a',)))
        for offset, value in ((0, 0), (8, 0), (16, 63), (24, len(raw) + 1), (32, 99999),
                              (40, 99999), (48, 2), (56, 1), (64, 8), (72, 0),
                              (80, 0), (88, 9999), (104, 9999), (136, 1), (144 + 32, 1)):
            broken = bytearray(raw); struct.pack_into('<Q', broken, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                materialize(bytes(broken), wire, self.lexer.integer_value)

    def test_manifest_rebinds_source_and_rejects_missing_artifact(self):
        self.assertIsNotNone(installed_source_types(str(self.manifest)))
        with patch('hepta.hia_source_types_native.SOURCE', self.folder / 'missing.hiaasm'):
            with self.assertRaises(FileNotFoundError): installed_source_types(str(self.manifest))
        bad = self.folder / 'bad.json'; value = json.loads(self.manifest.read_text())
        value['source_sha256'] = '0' * 64; bad.write_text(json.dumps(value))
        with self.assertRaises(ValueError): installed_source_types(str(bad))
        value['source_sha256'] = sha256(SOURCE.read_bytes()).hexdigest()
        value['image_path'] = 'absent.bin'; bad.write_text(json.dumps(value))
        with self.assertRaises(FileNotFoundError): installed_source_types(str(bad))
