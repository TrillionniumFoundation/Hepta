"""Real native declaration-name grammars versus independent source controls."""
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

from hepta.ast import HeptaError
from hepta.hia_source_names_native import SOURCE, SCHEMA, MAGIC, WORKSPACE, NativeSourceNames, materialize
from hepta.hia_source_lexer_native import SOURCE as LEXER_SOURCE, SCHEMA as LEXER_SCHEMA
from hepta.parser import Parser, parse

ROOT = Path(__file__).resolve().parents[1]
SELECTORS = {'HEPTA_HIA_SOURCE_TYPES_MANIFEST': '', 'HEPTA_HIA_SOURCE_NAMES_MANIFEST': '',
             'HEPTA_HIA_SOURCE_CLAUSES_MANIFEST': '', 'HEPTA_HIA_SOURCE_EXPRESSIONS_MANIFEST': '',
             'HEPTA_HIA_SOURCE_LEXER_MANIFEST': '', 'HEPTA_HIA_SOURCE_FRONTEND_MANIFEST': ''}
METHODS = {1: '_path', 2: '_type_params', 3: '_function_type_params'}


def expected_arena(mode, chars, rows):
    used = 64 + 64 * len(rows)
    return struct.pack('<8Q', MAGIC, len(rows), used, chars, chars, mode, 1, 0) + b''.join(
        struct.pack('<8Q', *row, 0, 0, 0) for row in rows)


REFERENCES = (
    (b'pkg::Name', 1, expected_arena(1, 9, [(1, 0, 3, 0, 0), (1, 5, 9, 0, 0)])),
    (b'<T,U>', 2, expected_arena(2, 5, [(2, 1, 2, 0, 0), (2, 3, 4, 0, 0)])),
    (b"<'a,T:Owned>", 3, expected_arena(3, 12, [(3, 2, 3, 0, 0), (2, 4, 5, 6, 11)])),
    (b')', 3, expected_arena(3, 0, [])),
)


def vm_window(wire, mode, begin=0, count=128, capacity=256, state_size=WORKSPACE):
    from tools.hia_selfhost_bulk import Body
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import execute_program
    b = Body(0)
    state = bytearray(state_size)
    if state_size >= 232:
        struct.pack_into('<Q', state, 224, mode)
    owners, views = [], []
    for size, initial in ((len(wire), wire), (capacity, b''), (state_size, state)):
        owner = b.value('buffer', 'buffer.new', [b.const('usize', size)])
        view = b.value('mutbuf', 'borrow.mut', [owner])
        for index, value in enumerate(initial):
            if value:
                b.effect('buffer.store', [view, b.const('usize', index), b.const('u8', value)])
        owners.append(owner); views.append(view)
    b.effect('loan.end', [views[0]])
    views[0] = b.value('readbuf', 'borrow.read', [owners[0]])
    status = b.value('u32', 'call', views, {'function': 'f0'})
    observed = [b.value('u8', 'buffer.load', [views[1], b.const('usize', index)])
                for index in range(begin, begin + count)]
    for view in views:
        b.effect('loan.end', [view])
    for owner in owners:
        b.effect('owner.drop', [owner])
    wrapper = ('hia-asm.v1 hepta.hia.program.v8 source_names_reference\nfn observe() -> (u32,'
        + ','.join(['u8'] * count) + ') effects(alloc,read,write,trap) entry(b0)\nblock b0()\n'
        + b.text() + '  ret(' + ','.join([status, *observed]) + ')\nend\n'
        + SOURCE.read_text().split('\n', 1)[1])
    outcome = execute_program(assemble_program(wrapper), 'observe', [], max_steps=2000000)
    assert outcome['status'] == 'returned', outcome
    return outcome['values'][0], bytes(outcome['values'][1:])


def check_reference_bytes():
    for wire, mode, expected in REFERENCES:
        for begin in range(0, len(expected), 128):
            code, raw = vm_window(wire, mode, begin, min(128, len(expected) - begin))
            assert code == len(expected)
            assert raw == expected[begin:begin + len(raw)]
    for wire, mode in ((b'::x', 1), (b'pkg::', 1), (b'<T,>', 2), (b'<T:>', 3)):
        assert vm_window(wire, mode)[0] == 0xffffffff


def outcome(source, mode, manifest=''):
    with patch.dict('os.environ', {**SELECTORS, 'HEPTA_HIA_SOURCE_NAMES_MANIFEST': manifest}):
        try:
            parser = Parser(source, 'names.hepta')
            result = getattr(parser, METHODS[mode])()
            return result, parser.position, parser.tokens, parser.current, parser.previous
        except HeptaError as error:
            return 'error', error.diagnostic.to_dict()


class SourceNamesSourceTests(unittest.TestCase):
    def test_generated_source_and_independent_VM_before_seed(self):
        from tools.generate_hia_source_names import document
        from hepta.hia_agent_assembly import render_assembly
        self.assertEqual(SOURCE.read_text(), render_assembly(document()))
        check_reference_bytes()


class SourceNamesNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check_reference_bytes()
        from tools.qualify_hia_selfhost import build_seed, compile_stage
        cls.temp = tempfile.TemporaryDirectory(prefix='hia-names-')
        cls.folder = Path(cls.temp.name)
        seed, _ = build_seed(cls.folder)
        source = (ROOT / 'examples/hia_bootstrap/selfhost.hiaasm').read_bytes()
        first, _ = compile_stage(cls.folder, 'B1', seed, source, image_format='seed-shared')
        second, _ = compile_stage(cls.folder, 'B2', first, source)
        assert first.read_bytes() == second.read_bytes()
        image, cls.receipt = compile_stage(cls.folder, 'names', second, SOURCE.read_bytes())
        cls.native = NativeSourceNames(image.read_bytes(), sha256(image.read_bytes()).hexdigest())
        cls.manifest = cls.folder / 'manifest.json'
        cls.manifest.write_text(json.dumps({'schema': SCHEMA, 'source_sha256': sha256(SOURCE.read_bytes()).hexdigest(),
            'image_path': image.name, 'image_sha256': sha256(image.read_bytes()).hexdigest(),
            'compiler_sha256': sha256(second.read_bytes()).hexdigest()}))
        lexer, _ = compile_stage(cls.folder, 'lexer', second, LEXER_SOURCE.read_bytes())
        (cls.folder / 'source-lexer').mkdir()
        (cls.folder / 'source-lexer/manifest.json').write_text(json.dumps({'schema': LEXER_SCHEMA,
            'source_sha256': sha256(LEXER_SOURCE.read_bytes()).hexdigest(), 'image_path': '../' + lexer.name,
            'image_sha256': sha256(lexer.read_bytes()).hexdigest(), 'compiler_sha256': sha256(second.read_bytes()).hexdigest()}))

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def compare(self, source, mode):
        self.assertEqual(outcome(source, mode, str(self.manifest)), outcome(source, mode), (source[:100], mode))

    def test_native_exact_independent_VM_bytes(self):
        for wire, mode, expected in REFERENCES:
            raw, _ = self.native.run(wire, mode)
            self.assertEqual(raw, expected)
        self.assertEqual(self.receipt['forbidden_compiler_modules_loaded'], [])

    def test_complete_qualified_name_and_parameter_grammars(self):
        for source in ('a', 'pkg::module_name::T', 'a /* π🙂 */ ::\r\n B', 'a<', 'a::b(c)',
                       'a::b::c ;', 'a' * 513, 'match', '', 'a::', 'a::fn', '::a'):
            self.compare(source, 1)
        for source in ('', ')', '<T>', '<T,U>', '<T,T>', '<T>>', '<T>=x', '<T,>', '<>',
                       '<T U>', "<'a>", '<T:Copy>', '<T', '<fn>', '<', '<T,\r\n/* π */U>'):
            self.compare(source, 2)
        for source in ('', '(', '<T>', "<'a,T:Owned,'b,U>", '<T,T:Owned>', '<T:Other>',
                       "<'a,'a>", '<T:Copy,U:Owned>', '<T>=x', '<T>>', '<T:>', '<T:mut>',
                       '<T,>', '<>', '<T U>', '<T::X>', "<'a:Copy>", '<T:Owned'):
            self.compare(source, 3)

    def test_seeded_differential_and_positions(self):
        rng = random.Random(0x4e414d45)
        for _ in range(150):
            names = [f'N{rng.randrange(10)}' for _ in range(rng.randrange(1, 10))]
            items = [rng.choice([name, name + ':Owned', "'life" + name]) for name in names]
            cases = [(' :: '.join(names), 1), ('<' + ', '.join(names) + '>', 2),
                     ('<' + ','.join(items) + '>', 3)]
            for source, mode in cases:
                self.compare('/* π🙂 */\r\n ' + source, mode)
                self.compare(source[:rng.randrange(len(source) + 1)], mode)

    def test_large_parameter_arena_and_capacity_retry(self):
        source = '<' + ','.join('T' + str(i) for i in range(2048)) + '>'
        self.compare(source, 2)
        self.compare(source, 3)

    def test_native_guards_and_transactional_refusal(self):
        for wire, mode, capacity, state_size, wanted in ((b'<T>', 2, 127, WORKSPACE, 0xfffffffe),
                (b'<T,>', 2, 256, WORKSPACE, 0xffffffff), (b'<T:>', 3, 256, WORKSPACE, 0xffffffff),
                (b'a', 0, 256, WORKSPACE, 0xfffffffd), (b'a', 1, 256, WORKSPACE - 1, 0xfffffffd)):
            source = ctypes.create_string_buffer(wire, len(wire))
            output = ctypes.create_string_buffer(b'\xa5' * (capacity + 8), capacity + 8)
            state = ctypes.create_string_buffer(b'\x5a' * (state_size + 8), state_size + 8)
            struct.pack_into('<Q', state, 224, mode)
            self.assertEqual(self.native._entry(source, len(wire), output, capacity, state, state_size), wanted)
            self.assertEqual(output.raw, b'\xa5' * (capacity + 8))
            self.assertEqual(state.raw[state_size:], b'\x5a' * 8)
            self.assertEqual(source.raw, wire)

    def test_arena_refuses_forged_ranges_roles_and_headers(self):
        wire, mode, raw = REFERENCES[2]
        for at, value in ((0, 0), (16, len(raw) - 1), (24, 1000), (40, 1),
                          (64, 1), (72, 300), (88, 2), (104, 1)):
            forged = bytearray(raw)
            struct.pack_into('<Q', forged, at, value)
            with self.assertRaises(ValueError):
                materialize(bytes(forged), wire, mode)

    def test_full_source_corpus_and_unavailable_reference_grammar(self):
        paths = sorted((ROOT / 'examples').rglob('*.hepta')) + sorted((ROOT / 'tests').rglob('*.hepta'))
        def observed(source, path):
            try:
                return parse(source, path)
            except HeptaError as error:
                return 'error', error.diagnostic.to_dict()
        self.assertGreater(len(paths), 0)
        print(f'native names corpus files: {len(paths)}')
        for path in paths:
            source = path.read_text()
            with patch.dict('os.environ', SELECTORS):
                expected = observed(source, str(path))
            with patch.dict('os.environ', {**SELECTORS, 'HEPTA_HIA_SOURCE_NAMES_MANIFEST': str(self.manifest)}), \
                 patch.object(Parser, '_reference_path', side_effect=AssertionError('foreign path grammar')), \
                 patch.object(Parser, '_reference_type_params', side_effect=AssertionError('foreign generic grammar')), \
                 patch.object(Parser, '_reference_function_type_params', side_effect=AssertionError('foreign parameter grammar')), \
                 patch('hepta.lexer.Lexer.tokenize', side_effect=AssertionError('foreign lexer')):
                self.assertEqual(observed(source, str(path)), expected, str(path))

    def test_concurrent_parser_instances_have_private_state(self):
        source = "module demo; struct Pair<'a,T> { x: read 'a T } fn f<T:Copy>(x:T) -> T effects{} { return x; }"
        with patch.dict('os.environ', SELECTORS):
            expected = parse(source)
        with patch.dict('os.environ', {**SELECTORS, 'HEPTA_HIA_SOURCE_NAMES_MANIFEST': str(self.manifest)}):
            with ThreadPoolExecutor(max_workers=8) as pool:
                self.assertEqual(list(pool.map(parse, [source] * 32)), [expected] * 32)


if __name__ == '__main__':
    unittest.main()
