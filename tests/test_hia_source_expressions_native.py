"""Independent VM bytes and native differential for the complete expression grammar."""
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

from hepta.ast import Expr, HeptaError, Span
from hepta.hia_source_expressions_native import (
    SOURCE, SCHEMA, WORKSPACE, NativeSourceExpressions, materialize,
    parse_expression, installed_source_expressions)
from hepta.hia_source_types_native import NativeSourceTypes
from hepta.hia_source_lexer_native import NativeSourceLexer
from hepta.parser import Parser, _MAX_NESTING, parse
ROOT = Path(__file__).resolve().parents[1]


def vm_window(wire, begin=0, count=128, capacity=4096, depth=128, minimum=0, allow=True):
    from tools.hia_selfhost_bulk import Body
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import execute_program
    b = Body(0); owners = []; views = []
    state = bytearray(WORKSPACE)
    struct.pack_into('<Q', state, 8528, depth)
    struct.pack_into('<2Q', state, 8640, minimum, int(allow))
    for size, initial in ((len(wire), wire), (capacity, b''), (WORKSPACE, state)):
        owner = b.value('buffer', 'buffer.new', [b.const('usize', size)])
        view = b.value('mutbuf', 'borrow.mut', [owner])
        for i, value in enumerate(initial):
            if value: b.effect('buffer.store', [view, b.const('usize', i), b.const('u8', value)])
        owners.append(owner); views.append(view)
    b.effect('loan.end', [views[0]])
    views[0] = b.value('readbuf', 'borrow.read', [owners[0]])
    code = b.value('u32', 'call', views, {'function':'f0'})
    raw = [b.value('u8', 'buffer.load', [views[1], b.const('usize', i)]) for i in range(begin, begin + count)]
    for view in views: b.effect('loan.end', [view])
    for owner in owners: b.effect('owner.drop', [owner])
    source = ('hia-asm.v1 hepta.hia.program.v8 source_expression_reference\n'
        'fn observe() -> (u32,' + ','.join(['u8'] * count) + ') effects(alloc,read,write,trap) entry(b0)\n'
        'block b0()\n' + b.text() + '  ret(' + ','.join([code, *raw]) + ')\nend\n'
        + SOURCE.read_text().split('\n', 1)[1])
    result = execute_program(assemble_program(source), 'observe', [], max_steps=4000000)
    assert result['status'] == 'returned', result
    code, *raw = result['values']
    return code, bytes(raw)


def vm_arena(wire):
    size, first = vm_window(wire)
    if size > 4096: return size, None
    chunks = [first]
    for begin in range(128, size, 128):
        again, chunk = vm_window(wire, begin, min(128, size - begin))
        assert again == size
        chunks.append(chunk)
    return size, b''.join(chunks)[:size]


def references():
    result = []
    for wire in (b'17', b'a + 2', b'f(1,2)'):
        size, raw = vm_arena(wire)
        assert size == len(raw)
        result.append((wire, raw))
    for wire in (b'1(2)', b'f(', b'"C"', b'a +'):
        assert vm_window(wire)[0] == 0xffffffff
    return result


def outcome(source, native=None, types=None, lexer=None, *, minimum=0, allow=True, depth=0):
    try:
        parser = Parser(source, 'expressions.hepta'); parser.depth = depth
        if native is None:
            value = parser._expr(minimum, allow)
        else:
            with parser._nested():
                value = parse_expression(parser, native, types, lexer, minimum=minimum,
                    allow_struct=allow, max_depth=_MAX_NESTING - parser.depth + 1,
                    nesting_limit=_MAX_NESTING)
        return ('expr', value, parser.position, parser.tokens, parser.current,
                parser.previous, parser.depth, parser.qualified_expressions)
    except HeptaError as error:
        return ('error', error.diagnostic.to_dict())


class SourceExpressionsSourceTests(unittest.TestCase):
    def test_generated_HIA_source_is_exact_and_within_existing_compiler_limits(self):
        from tools.generate_hia_source_expressions import document
        from hepta.hia_agent_assembly import render_assembly
        data = document()
        self.assertEqual(SOURCE.read_text(), render_assembly(data))
        self.assertLessEqual(len(data['functions']), 128)
        self.assertLessEqual(sum(len(fn['blocks']) for fn in data['functions']), 1536)
        self.assertLessEqual(sum(len(b['ops']) for fn in data['functions'] for b in fn['blocks']), 8192)
        self.assertLessEqual(len(SOURCE.read_bytes()), 1048576)


class SourceExpressionsNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.references = references()  # All byte oracles execute before B0.
        from tools.qualify_hia_selfhost import build_seed, compile_stage
        cls.temporary = tempfile.TemporaryDirectory(prefix='hia-source-expressions-')
        cls.folder = Path(cls.temporary.name)
        seed, _ = build_seed(cls.folder)
        compiler = (ROOT / 'examples/hia_bootstrap/selfhost.hiaasm').read_bytes()
        first, _ = compile_stage(cls.folder, 'B1', seed, compiler, image_format='seed-shared')
        second, _ = compile_stage(cls.folder, 'B2', first, compiler)
        assert first.read_bytes() == second.read_bytes()
        image, cls.receipt = compile_stage(cls.folder, 'source-expressions', second, SOURCE.read_bytes())
        cls.native = NativeSourceExpressions(image.read_bytes(), sha256(image.read_bytes()).hexdigest())
        cls.manifest = cls.folder / 'manifest.json'
        cls.manifest.write_text(json.dumps({'schema':SCHEMA, 'source_sha256':sha256(SOURCE.read_bytes()).hexdigest(),
            'image_path':image.name, 'image_sha256':sha256(image.read_bytes()).hexdigest(),
            'compiler_sha256':sha256(second.read_bytes()).hexdigest()}))
        source = ROOT / 'examples/hia_bootstrap/source_types.hiaasm'
        image, _ = compile_stage(cls.folder, 'source-types', second, source.read_bytes())
        cls.types = NativeSourceTypes(image.read_bytes(), sha256(image.read_bytes()).hexdigest())
        folder = cls.folder / 'source-types'; folder.mkdir()
        (folder / 'manifest.json').write_text(json.dumps({'schema':'hepta.hia.source-types-native.v1',
            'source_sha256':sha256(source.read_bytes()).hexdigest(), 'image_path':'../' + image.name,
            'image_sha256':sha256(image.read_bytes()).hexdigest(), 'compiler_sha256':sha256(second.read_bytes()).hexdigest()}))
        source = ROOT / 'examples/hia_bootstrap/source_lexer.hiaasm'
        image, _ = compile_stage(cls.folder, 'lexer', second, source.read_bytes())
        cls.lexer = NativeSourceLexer(image.read_bytes(), sha256(image.read_bytes()).hexdigest())
        folder = folder / 'source-lexer'; folder.mkdir()
        (folder / 'manifest.json').write_text(json.dumps({'schema':'hepta.hia.source-lexer-native.v3',
            'source_sha256':sha256(source.read_bytes()).hexdigest(), 'image_path':'../../' + image.name,
            'image_sha256':sha256(image.read_bytes()).hexdigest(), 'compiler_sha256':sha256(second.read_bytes()).hexdigest()}))

    @classmethod
    def tearDownClass(cls): cls.temporary.cleanup()

    def compare(self, source, **kwargs):
        self.assertEqual(outcome(source, self.native, self.types, self.lexer, **kwargs),
                         outcome(source, **kwargs), (source[:200], kwargs))

    def test_every_native_byte_matches_independent_preseed_VM(self):
        for wire, expected in self.references:
            actual, _ = self.native.run(wire, max_depth=128)
            self.assertEqual(actual, expected)
        self.assertEqual(self.receipt['forbidden_compiler_modules_loaded'], [])

    def test_all_existing_expression_productions_and_precedence(self):
        rows = ('0', '0x1234', '0b1_010', '123.5e-2', 'true', 'false', 'name',
            '1 + 2 * 3 - 4 / 2 % 3', 'a << 2 + 1 >> 3', 'a | b ^ c & d',
            'a == b != c < d <= e > f >= g && h || i', '-a * !b', 'read mut move a[1].match',
            'f()', 'f(1, 2,)', '(f)(1)', '((f))::<u8>', 'f::<u8>(1)',
            'pkg::Type::<u8>::Variant(3)', 'f::<X<X<T>>, raw const i64>(a)',
            'a as u8 as u64 + 1', 'a as X<X<T>> >> 2', 'a as X<T>=0',
            '((a + b))', '[]', '[1,2,]', '[[1], [2]][0][1]',
            'Pair { x: 1, match: f(2), }', 'pkg::Pair::<u64> { x: [1,2], y: A{} }',
            'f(Pair{x: 1}, [2,3]).x[0]', 'a + b { x:1 }', 'a + (b { x:1 })',
            'f::<[u8;0xff]>(a)', "x as read 'a raw const Buffer<u8>",
            '/* π🙂 */\r\n  f ( a + 2,\r\n b as u8 ) ; trailing',
            'f::<X<T>>=3', 'x as X<T>>3', 'T >> 0', 'x >= y')
        for source in rows:
            with self.subTest(source=source): self.compare(source)
        for source in ('a { x:1 }', 'a + b { x:1 }', '-a { x:1 }', 'f(A{x:1})', 'a[A{x:1}]'):
            self.compare(source, allow=False)
        for minimum in range(13): self.compare('a as u8 + b * c << d && e', minimum=minimum)

    def test_exact_errors_and_depth_including_cast_and_generic_type_frames(self):
        rows = ('', ')', ']', 'fn', '"C"', '1(2)', '(a+b)(2)', 'a.x(1)', 'f(,)',
            'f(1', '[1', '[1,,2]', '()', '(1]', 'a.', 'a.raw', 'A{x 1}', 'A{x:}',
            'A{x:1 y:2}', 'A{x:1,,}', 'a::', 'a::raw', 'a::<>', 'a::<u8,>',
            'a::<u8>::<u32>', 'a::<u8', 'a as', 'a as Buffer', 'a as [u8; -1]',
            'a +', 'a + * b', 'raw', 'A{match:1}.match')
        for source in rows:
            for prefix in ('', '/* π🙂 */\r\n  '):
                with self.subTest(source=(prefix+source)[:120]): self.compare(prefix + source)
        for nesting in (94, 95, 96, 97):
            self.compare('(' * nesting + 'x' + ')' * nesting)
            self.compare('x as ' + '[' * nesting + 'u8' + ']' * nesting)
        for depth in (1, 40, 94, 95, 96):
            for source in ('f(1)', 'x as u8', 'f::<u8>(x)', '-x'):
                self.compare(source, depth=depth)

    def test_deterministic_valid_and_malformed_expression_composition(self):
        rng = random.Random(0xE8712026)
        def make(depth):
            if not depth: return rng.choice(['x', '17', 'true', '1.5', 'pkg::value'])
            a = make(depth - 1); b = make(depth - 1)
            return rng.choice(['(' + a + ')', a + ' + ' + b, a + ' * ' + b,
                'f(' + a + ',' + b + ')', '[' + a + ',' + b + ']',
                'Pair{x:' + a + ',y:' + b + '}', '!' + a, '(' + a + ') as u64',
                'f::<X<u8>>(' + a + ')', '(' + a + ')[0]', '(' + a + ').x'])
        for _ in range(180):
            source = make(rng.randrange(0, 5)); self.compare(source)
            self.compare(source[:rng.randrange(len(source) + 1)])

    def test_actual_repository_expression_entrypoints_match_reference(self):
        observations = []
        original = Parser._expr
        def capture(parser, minimum=0, allow_struct=True):
            position = parser.current.span.start
            depth = parser.depth
            observations.append((parser.source[position:], minimum, allow_struct, depth))
            return original(parser, minimum, allow_struct)
        paths = sorted((ROOT / 'examples').rglob('*.hepta')) + sorted((ROOT / 'tests').rglob('*.hepta'))
        with patch.object(Parser, '_expr', capture):
            for path in paths:
                try: parse(path.read_text(), str(path))
                except HeptaError: pass
        for source, minimum, allow, depth in observations[:350]:
            self.compare(source, minimum=minimum, allow=allow, depth=depth)
        self.assertGreater(len(observations), 20)

    def test_concurrent_actual_images_do_not_call_host_expression_or_type_grammar(self):
        sources = ['f::<X<u8>>(Pair{x:1,y:2})[0].x as u64', '1+2*3', 'pkg::Pair{x:[1,2]}'] * 12
        expected = [outcome(source) for source in sources]
        # Tokens are created by the actual native lexer; no legacy grammar is
        # involved in the parser object used solely as the surrounding cursor.
        def selected(source):
            parser = object.__new__(Parser)
            parser.source = source; parser.path = 'expressions.hepta'
            parser.tokens = self.lexer.tokenize(source, parser.path)
            parser.position = 0; parser.depth = 0; parser.qualified_expressions = []
            with parser._nested():
                value = parse_expression(parser, self.native, self.types, self.lexer,
                    minimum=0, allow_struct=True, max_depth=96, nesting_limit=96)
            return ('expr', value, parser.position, parser.tokens, parser.current,
                    parser.previous, parser.depth, parser.qualified_expressions)
        with patch.object(Parser, '_expr', side_effect=AssertionError('foreign expression grammar')), \
             patch.object(Parser, '_reference_type', side_effect=AssertionError('foreign type grammar')), \
             patch('hepta.lexer.Lexer.tokenize', side_effect=AssertionError('foreign lexer')):
            with ThreadPoolExecutor(max_workers=8) as pool:
                self.assertEqual(list(pool.map(selected, sources)), expected)

    def test_actual_selected_full_parser_corpus_without_reference_expression_or_type_grammar(self):
        paths = sorted((ROOT / 'examples').rglob('*.hepta')) + sorted((ROOT / 'tests').rglob('*.hepta'))
        def call(path, manifest):
            with patch.dict('os.environ', {'HEPTA_HIA_SOURCE_EXPRESSIONS_MANIFEST':manifest,
                    'HEPTA_HIA_SOURCE_TYPES_MANIFEST':'', 'HEPTA_HIA_SOURCE_LEXER_MANIFEST':'',
                    'HEPTA_HIA_SOURCE_NAMES_MANIFEST':'', 'HEPTA_HIA_SOURCE_CLAUSES_MANIFEST':'',
                    'HEPTA_HIA_SOURCE_FRONTEND_MANIFEST':''}):
                try: return ('tree', parse(path.read_text(), str(path)))
                except HeptaError as error: return ('error', error.diagnostic.to_dict())
        expected = [call(path, '') for path in paths]
        with patch.object(Parser, '_reference_expr', side_effect=AssertionError('foreign Pratt grammar')), \
             patch.object(Parser, '_prefix', side_effect=AssertionError('foreign prefix grammar')), \
             patch.object(Parser, '_reference_type', side_effect=AssertionError('foreign type grammar')), \
             patch('hepta.lexer.Lexer.tokenize', side_effect=AssertionError('foreign lexer')):
            observed = [call(path, str(self.manifest)) for path in paths]
        self.assertEqual(observed, expected)
        self.assertGreater(len(paths), 0)
        print(f'native expressions corpus files: {len(paths)}')

    def test_explicit_native_frame_boundary_avoids_host_recursion(self):
        for count, valid in ((127, True), (128, False)):
            wire = ('(' * count + 'x' + ')' * count).encode()
            raw, state = self.native.run(wire, max_depth=128)
            if valid:
                value, _, chars, consumed, _ = materialize(raw, wire, self.types, self.lexer)
                self.assertEqual(value.kind, 'name'); self.assertEqual(value.value, 'x')
                self.assertEqual(value.span, Span(0, len(wire), 1, 1))
                self.assertEqual(chars, len(wire)); self.assertEqual(consumed, len(wire))
            else:
                self.assertIsNone(raw)
                self.assertEqual(struct.unpack_from('<Q', state, 8592)[0], 1)

    def test_transactional_refusals_poisoned_state_and_capacity_scaling(self):
        for wire, capacity, state_size, depth, minimum, allow, wanted in (
            (b'x', 1, WORKSPACE, 128, 0, 1, 0xfffffffe),
            (b'x', 512, WORKSPACE-1, 128, 0, 1, 0xfffffffd),
            (b'x', 512, WORKSPACE, 0, 0, 1, 0xfffffffd),
            (b'x', 512, WORKSPACE, 129, 0, 1, 0xfffffffd),
            (b'x', 512, WORKSPACE, 128, 13, 1, 0xfffffffd),
            (b'x', 512, WORKSPACE, 128, 0, 2, 0xfffffffd),
            (b'f(', 512, WORKSPACE, 128, 0, 1, 0xffffffff),
            (b'1(2)', 512, WORKSPACE, 128, 0, 1, 0xffffffff)):
            source = ctypes.create_string_buffer(wire, len(wire))
            output = ctypes.create_string_buffer(b'\xa5' * (capacity + 8), capacity + 8)
            state = ctypes.create_string_buffer(b'\x5a' * (state_size + 8), state_size + 8)
            struct.pack_into('<Q', state, 8528, depth); struct.pack_into('<2Q', state, 8640, minimum, allow)
            result = self.native._entry(source, len(wire), output, capacity, state, state_size)
            self.assertEqual(result, wanted); self.assertEqual(output.raw, b'\xa5' * (capacity + 8))
            self.assertEqual(state.raw[state_size:], b'\x5a' * 8); self.assertEqual(source.raw, wire)
        raw, _ = self.native.run(('[' + ','.join(['1'] * 200) + ']').encode(), max_depth=128)
        self.assertGreater(len(raw), 4096)

    def test_arena_rejects_unknown_events_stack_underflow_and_ranges(self):
        wire = b'f(1,2)'; raw, _ = self.native.run(wire, max_depth=128)
        value, _, _, _, _ = materialize(raw, wire, self.types, self.lexer)
        self.assertEqual(value.kind, 'call')
        for offset, value in ((0,0), (8,0), (16,len(raw)+1), (24,999999), (32,999999), (40,2),
            (48,999), (56,1), (64,999), (72,99), (80,9999), (112,999), (136,1)):
            broken = bytearray(raw); struct.pack_into('<Q', broken, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                materialize(bytes(broken), wire, self.types, self.lexer)

    def test_manifests_bind_expression_type_and_lexer_source_bytes(self):
        self.assertIsNotNone(installed_source_expressions(str(self.manifest)))
        with patch('hepta.hia_source_expressions_native.SOURCE', self.folder / 'missing.hiaasm'):
            with self.assertRaises(FileNotFoundError): installed_source_expressions(str(self.manifest))
        bad = self.folder / 'bad.json'; value = json.loads(self.manifest.read_text())
        value['source_sha256'] = '0' * 64; bad.write_text(json.dumps(value))
        with self.assertRaises(ValueError): installed_source_expressions(str(bad))


if __name__ == '__main__': unittest.main()
