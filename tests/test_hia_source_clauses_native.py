"""Real HIA clauses: independent VM bytes, native grammar and actual callers."""
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

from hepta.ast import HeptaError
from hepta.hia_source_clauses_native import (
    MAGIC, SCHEMA, SOURCE, WORKSPACE_HEADER, NativeSourceClauses,
    installed_source_clauses, materialize, parse_clause, workspace_size,
)
from hepta.hia_source_lexer_native import NativeSourceLexer
from hepta.parser import Parser, parse

ROOT = Path(__file__).resolve().parents[1]
SELECTORS = {name: '' for name in (
    'HEPTA_HIA_SOURCE_FRONTEND_MANIFEST', 'HEPTA_HIA_SOURCE_NAMES_MANIFEST',
    'HEPTA_HIA_SOURCE_EXPRESSIONS_MANIFEST', 'HEPTA_HIA_SOURCE_TYPES_MANIFEST',
    'HEPTA_HIA_SOURCE_CLAUSES_MANIFEST', 'HEPTA_HIA_SOURCE_LEXER_MANIFEST')}


def vm_window(wire, mode, begin=0, count=128, capacity=512, slots=16):
    from tools.hia_selfhost_bulk import Body
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import execute_program
    state = bytearray(WORKSPACE_HEADER + slots * 16)
    struct.pack_into('<Q', state, 208, mode)
    struct.pack_into('<Q', state, 224, 1)
    b = Body(0)
    owners, views = [], []
    for size, initial in ((len(wire), wire), (capacity, b''), (len(state), state)):
        owner = b.value('buffer', 'buffer.new', [b.const('usize', size)])
        view = b.value('mutbuf', 'borrow.mut', [owner])
        for i, value in enumerate(initial):
            if value:
                b.effect('buffer.store', [view, b.const('usize', i), b.const('u8', value)])
        owners.append(owner)
        views.append(view)
    b.effect('loan.end', [views[0]])
    views[0] = b.value('readbuf', 'borrow.read', [owners[0]])
    code = b.value('u32', 'call', views, {'function': 'f0'})
    raw = [b.value('u8', 'buffer.load', [views[1], b.const('usize', i)])
           for i in range(begin, begin + count)]
    for view in views:
        b.effect('loan.end', [view])
    for owner in owners:
        b.effect('owner.drop', [owner])
    source = ('hia-asm.v1 hepta.hia.program.v8 source_clause_reference\n'
        'fn observe() -> (u32,' + ','.join(['u8'] * count) + ') '
        'effects(alloc,read,write,trap) entry(b0)\nblock b0()\n' + b.text()
        + '  ret(' + ','.join([code, *raw]) + ')\nend\n' + SOURCE.read_text().split('\n', 1)[1])
    result = execute_program(assemble_program(source), 'observe', [], max_steps=2000000)
    assert result['status'] == 'returned', result
    code, *raw = result['values']
    return code, bytes(raw)


def reference_rows():
    """Manually specified protocol bytes, independently executed before B0."""
    cases = [
        (b'effects {}', 1, []),
        (b'effects {io,unsafe}', 1, [(9, 11, 0, 0, 0), (12, 18, 0, 0, 0)]),
        (b'resources {n=7; yes=true;}', 2,
            [(11, 12, 1, 13, 14), (16, 19, 4, 20, 24)]),
    ]
    observed = []
    for wire, mode, rows in cases:
        used = 64 + 40 * len(rows)
        expected = struct.pack('<8Q', MAGIC, 1, mode, len(rows), used, len(wire), len(wire), 0)
        expected += b''.join(struct.pack('<5Q', *row) for row in rows)
        raw = bytearray()
        for begin in range(0, used, 128):
            status, chunk = vm_window(wire, mode, begin, min(128, used - begin))
            assert status == used, status
            raw.extend(chunk)
        assert bytes(raw) == expected, (wire, bytes(raw), expected)
        observed.append((wire, mode, expected))
    for wire, mode in ((b'effects {io,io}', 1), (b'effects {read}', 1),
                       (b'resources {n=7;n=8;}', 2), (b'resources {n=-1;}', 2)):
        assert vm_window(wire, mode, count=1)[0] == 0xffffffff
    return observed


def outcome(source, mode, selected='', *, native=None, lexer=None):
    with patch.dict('os.environ', {**SELECTORS, 'HEPTA_HIA_SOURCE_CLAUSES_MANIFEST': selected}):
        try:
            parser = Parser(source, 'clauses.hepta')
            if native is not None:
                value = parse_clause(parser, native, lexer, mode)
            else:
                value = parser._effects() if mode == 1 else parser._resources()
            return ('clause', value, parser.position, parser.current, parser.previous, parser.tokens)
        except HeptaError as error:
            return ('error', error.diagnostic.to_dict())


class SourceClausesSourceTests(unittest.TestCase):
    def test_actual_generated_HIA_and_independent_VM_before_seed(self):
        from tools.generate_hia_source_clauses import document
        from hepta.hia_agent_assembly import render_assembly
        self.assertEqual(SOURCE.read_text(), render_assembly(document()))
        self.assertEqual(len(reference_rows()), 3)


class SourceClausesNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.references = reference_rows()
        from tools.qualify_hia_selfhost import build_seed, compile_stage
        from hepta.hia_source_lexer_native import SCHEMA as LEXER_SCHEMA
        cls.temporary = tempfile.TemporaryDirectory(prefix='hia-source-clauses-')
        cls.folder = Path(cls.temporary.name)
        seed, _ = build_seed(cls.folder)
        compiler_source = (ROOT / 'examples/hia_bootstrap/selfhost.hiaasm').read_bytes()
        first, _ = compile_stage(cls.folder, 'B1', seed, compiler_source, image_format='seed-shared')
        second, _ = compile_stage(cls.folder, 'B2', first, compiler_source)
        assert first.read_bytes() == second.read_bytes()
        image, cls.receipt = compile_stage(cls.folder, 'source-clauses', second, SOURCE.read_bytes())
        cls.native = NativeSourceClauses(image.read_bytes(), sha256(image.read_bytes()).hexdigest())
        cls.manifest = cls.folder / 'manifest.json'
        cls.manifest.write_text(json.dumps({'schema': SCHEMA,
            'source_sha256': sha256(SOURCE.read_bytes()).hexdigest(), 'image_path': image.name,
            'image_sha256': sha256(image.read_bytes()).hexdigest(),
            'compiler_sha256': sha256(second.read_bytes()).hexdigest()}))
        lexer_source = ROOT / 'examples/hia_bootstrap/source_lexer.hiaasm'
        lexer_image, _ = compile_stage(cls.folder, 'lexer', second, lexer_source.read_bytes())
        cls.lexer = NativeSourceLexer(lexer_image.read_bytes(), sha256(lexer_image.read_bytes()).hexdigest())
        folder = cls.folder / 'source-lexer'
        folder.mkdir()
        (folder / 'manifest.json').write_text(json.dumps({'schema': LEXER_SCHEMA,
            'source_sha256': sha256(lexer_source.read_bytes()).hexdigest(),
            'image_path': '../' + lexer_image.name, 'image_sha256': sha256(lexer_image.read_bytes()).hexdigest(),
            'compiler_sha256': sha256(second.read_bytes()).hexdigest()}))

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def compare(self, source, mode):
        expected = outcome(source, mode)
        self.assertEqual(outcome(source, mode, native=self.native, lexer=self.lexer), expected, repr(source[:160]))
        self.assertEqual(outcome(source, mode, str(self.manifest)), expected, repr(source[:160]))

    def test_native_every_byte_equals_independent_VM_before_seed(self):
        for wire, mode, expected in self.references:
            raw, _ = self.native.run(wire, mode=mode)
            self.assertEqual(raw, expected)
        self.assertEqual(self.receipt['forbidden_compiler_modules_loaded'], [])

    def test_complete_effects_resources_and_exact_consumed_cursor(self):
        for source in ('effects {}', 'effects {io,alloc,unsafe,}',
                       'effects{a_b,_x,long_name} resources {n=5;}',
                       'effects/* π🙂 */{ io,\r\n unsafe } fn'):
            self.compare(source, 1)
        for source in ('resources {}', 'resources{n=0xff;enabled=true;disabled=false;}',
                       'resources {ratio=1.5; tiny=5e-324; huge=1.7976931348623157e308;}',
                       'resources {n=0b10_01;oct=0o77;} {return x;}',
                       'resources/*π🙂*/{n=123;\r\n r=2.5e-3;} effects{}',
                       'resources{n=' + '9' * 4096 + ';}'):
            self.compare(source, 2)

    def test_exact_diagnostic_codes_messages_spans_and_lexical_precedence(self):
        for source in ('', '{}', 'effects', 'effects (', 'effects {read}', 'effects {io io}',
                       'effects {io,,}', 'effects {io;}', 'effects {io,io}',
                       'effects {unsafe,unsafe}', 'effects {io,io,1}',
                       'effects {io', 'effects {,}', 'effects {1}'):
            for prefix in ('', '/* π🙂 */\r\n  '):
                self.compare(prefix + source, 1)
        for source in ('', '{}', 'resources', 'resources (', 'resources{read=0;}',
                       'resources{a=0;a=1;}', 'resources{a}', 'resources{a:0;}',
                       'resources{a=-1;}', 'resources{a=read;}', 'resources{a="C";}',
                       'resources{a=1}', 'resources{a=0,}', 'resources{a=0;',
                       'resources{a=1e309;}', 'resources{a=0__1;}', 'resources{a=1e-;}',
                       'resources{a=1;b=2;b=3;}', 'resources{a=1;a=}',
                       'resources{a=1;a=2;b=-1;}', 'resources{a=1;} #'):
            for prefix in ('', '/* π🙂 */\r\n  '):
                self.compare(prefix + source, 2)

    def test_deterministic_fuzzed_complete_and_truncated_clauses(self):
        rng = random.Random(0xc1a052026)
        for _ in range(100):
            names = [f'n{rng.randrange(10)}' for _ in range(rng.randrange(1, 12))]
            effects = 'effects {' + ','.join(names) + '}'
            resources = 'resources {' + ''.join(f'{n}={rng.choice(["0x7f", "true", "false", "1.25e3"])};' for n in names) + '}'
            for source, mode in ((effects, 1), (resources, 2)):
                self.compare(source, mode)
                self.compare(source[:rng.randrange(len(source) + 1)], mode)

    def test_collision_resolution_large_clauses_and_private_concurrency(self):
        names = []
        for i in range(1000):
            name = f'name{i}'
            h = 14695981039346656037
            for byte in name.encode():
                h = ((h ^ byte) * 1099511628211) & ((1 << 64) - 1)
            if h & 15 == 0:
                names.append(name)
            if len(names) == 8:
                break
        self.compare('effects {' + ','.join(names) + '}', 1)
        self.compare('effects {' + ','.join(names + [names[-1]]) + '}', 1)
        source = 'resources{' + ''.join(f'key{i}={i};' for i in range(2048)) + '}'
        self.compare(source, 2)
        wire = source.encode()
        expected, _ = self.native.run(wire, mode=2)
        with ThreadPoolExecutor(max_workers=8) as pool:
            outputs = list(pool.map(lambda _: self.native.run(wire, mode=2)[0], range(24)))
        self.assertEqual(outputs, [expected] * 24)
        self.assertEqual(workspace_size(0), WORKSPACE_HEADER + 32)
        self.assertLess(workspace_size(2048), len(wire) * 4)

    def test_actual_repository_parser_callers_match_default_AST(self):
        paths = sorted((ROOT / 'tests').rglob('*.hepta')) + sorted((ROOT / 'examples').rglob('*.hepta'))
        self.assertTrue(paths, 'actual parser source corpus must not be empty')
        for path in paths:
            source = path.read_text()
            def call(selected):
                with patch.dict('os.environ', {**SELECTORS, 'HEPTA_HIA_SOURCE_CLAUSES_MANIFEST': selected}):
                    try:
                        return ('tree', parse(source, str(path)))
                    except HeptaError as error:
                        return ('error', error.diagnostic.to_dict())
            with self.subTest(path=str(path)):
                self.assertEqual(call(str(self.manifest)), call(''))
        print(f'HIA source clauses: {len(paths)} actual source files compared', flush=True)

    def test_actual_functions_no_reference_lexer_or_clause_grammar_and_no_fallback(self):
        source = ('module demo; extern "C" fn c(x:u64)->u64 effects{io,unsafe}; '
            'fn f(x:u64)->u64 effects{} resources{fuel=4096;ratio=1.5;allow=true;} {return x;}')
        with patch.dict('os.environ', SELECTORS):
            expected = parse(source)
        with patch.dict('os.environ', {**SELECTORS, 'HEPTA_HIA_SOURCE_CLAUSES_MANIFEST': str(self.manifest)}), \
             patch.object(Parser, '_reference_effects', side_effect=AssertionError('foreign effects grammar')), \
             patch.object(Parser, '_reference_resources', side_effect=AssertionError('foreign resources grammar')), \
             patch('hepta.lexer.Lexer.tokenize', side_effect=AssertionError('foreign lexer')):
            with ThreadPoolExecutor(max_workers=8) as pool:
                self.assertEqual(list(pool.map(parse, [source] * 24)), [expected] * 24)

    def test_transactional_rejections_measurement_and_poisoned_guards(self):
        cases = ((b'effects {}', 1, 1, 2, 63, 0xfffffffe),
                 (b'effects {io,io}', 1, 1, 4, 512, 0xffffffff),
                 (b'resources{n=1;n=2;}', 2, 1, 4, 512, 0xffffffff),
                 (b'resources{n=-1;}', 2, 1, 4, 512, 0xffffffff),
                 (b'effects {a,b}', 1, 1, 2, 512, 0xffffffff),
                 (b'effects {}', 1, 1, 3, 512, 0xfffffffd),
                 (b'effects {}', 9, 1, 2, 512, 0xfffffffd),
                 (b'effects {}', 1, 2, 2, 512, 0xfffffffd),
                 (b'effects {a,\xc0\x80}', 1, 1, 4, 512, 0xffffffff))
        for wire, mode, command, slots, capacity, wanted in cases:
            source = ctypes.create_string_buffer(wire, len(wire))
            output = ctypes.create_string_buffer(b'\xa5' * (capacity + 8), capacity + 8)
            state_size = WORKSPACE_HEADER + slots * 16
            state = ctypes.create_string_buffer(b'\x5a' * (state_size + 8), state_size + 8)
            struct.pack_into('<Q', state, 208, mode)
            struct.pack_into('<Q', state, 224, command)
            result = self.native._entry(source, len(wire), output, capacity, state, state_size)
            self.assertEqual(result, wanted, (wire, mode, command, slots))
            self.assertEqual(output.raw, b'\xa5' * (capacity + 8))
            self.assertEqual(state.raw[state_size:], b'\x5a' * 8)
            self.assertEqual(source.raw, wire)
        wire = b'effects {io,unsafe}'
        source = ctypes.create_string_buffer(wire, len(wire))
        output = ctypes.create_string_buffer(b'\xa5' * 16, 16)
        state = ctypes.create_string_buffer(WORKSPACE_HEADER)
        struct.pack_into('<Q', state, 208, 1)
        measured = self.native._entry(source, len(wire), output, 16, state, WORKSPACE_HEADER)
        self.assertEqual(measured, 144)
        self.assertEqual(output.raw, b'\xa5' * 16)

    def test_arena_rejects_overlap_wrong_kinds_cursor_and_duplicate_values(self):
        wire = b'resources {n=7; yes=true;}'
        raw, _ = self.native.run(wire, mode=2)
        self.assertEqual(materialize(raw, wire, self.lexer, mode=2)[0], {'n': 7, 'yes': True})
        for offset, value in ((0, 0), (8, 2), (16, 1), (24, 100), (32, 64),
                              (40, 9999), (48, 9999), (56, 1), (64, 9999),
                              (72, 64), (80, 0), (88, 0), (96, 9999),
                              (104, 11), (112, 12), (120, 99)):
            broken = bytearray(raw)
            struct.pack_into('<Q', broken, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                materialize(bytes(broken), wire, self.lexer, mode=2)

    def test_selected_manifest_rejects_drift_or_missing_image(self):
        self.assertIsNotNone(installed_source_clauses(str(self.manifest)))
        bad = self.folder / 'bad.json'
        value = json.loads(self.manifest.read_text())
        value['source_sha256'] = '0' * 64
        bad.write_text(json.dumps(value))
        with self.assertRaises(ValueError):
            installed_source_clauses(str(bad))
        value['source_sha256'] = sha256(SOURCE.read_bytes()).hexdigest()
        value['image_path'] = 'absent.bin'
        bad.write_text(json.dumps(value))
        with patch.dict('os.environ', {**SELECTORS, 'HEPTA_HIA_SOURCE_CLAUSES_MANIFEST': str(bad)}):
            with self.assertRaises(FileNotFoundError):
                Parser('fn f()->u8 effects{} {return 0;}')


if __name__ == '__main__':
    unittest.main()
