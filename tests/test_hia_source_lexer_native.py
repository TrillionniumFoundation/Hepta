"""Independent source lexing, real HIA successors, spans and refusals."""
from __future__ import annotations
import ctypes
import json
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from pathlib import Path
import random
import tempfile
import unittest
from unittest.mock import patch

from hepta.ast import HeptaError
from hepta.lexer import tokenize,KEYWORDS
from hepta.hia_source_lexer_native import (NativeSourceLexer,SOURCE,materialize,
    KEYWORD_ORDER,PAIR_ORDER)
from tools.generate_hia_source_lexer import document

ROOT=Path(__file__).resolve().parents[1]


def outcome(call,source):
    try:return ('tokens',call(source,'lexical-input.hepta'))
    except HeptaError as error:return ('diagnostic',error.diagnostic.to_dict())


def vm_references():
    from tests.test_hia_json_decode_native import vm_arena
    for source in ('','fn x','/* π */\r\nfn','0x3f','"🙂"',"'a"):
        wire=source.encode();code,raw=vm_arena(wire,source_path=SOURCE,sizes=(224,128))
        assert code<=224,(source,code)
        assert materialize(source,'<input>',wire,raw)==tokenize(source),source
    code,_=vm_arena(b'1__2',source_path=SOURCE,sizes=(224,128))
    assert code==0xffffffff


class SourceLexerSourceTests(unittest.TestCase):
    def test_checked_in_source_and_keyword_protocol_are_exact(self):
        from hepta.hia_agent_assembly import render_assembly,assemble_program
        self.assertEqual(render_assembly(document()),SOURCE.read_text())
        self.assertEqual(frozenset(KEYWORD_ORDER),KEYWORDS)
        self.assertEqual(len(assemble_program(SOURCE.read_bytes()).as_dict()['functions']),19)


class SourceLexerNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        vm_references()  # Before the seed, not a native-generated oracle.
        from tools.qualify_hia_selfhost import build_seed,compile_stage
        cls.temporary=tempfile.TemporaryDirectory(prefix='hia-source-lexer-')
        cls.folder=Path(cls.temporary.name)
        seed,_=build_seed(cls.folder)
        compiler=(ROOT/'examples/hia_bootstrap/selfhost.hiaasm').read_bytes()
        first,_=compile_stage(cls.folder,'B1',seed,compiler,image_format='seed-shared')
        second,_=compile_stage(cls.folder,'B2',first,compiler)
        assert first.read_bytes()==second.read_bytes()
        image,cls.receipt=compile_stage(cls.folder,'source-lexer',second,SOURCE.read_bytes())
        raw=image.read_bytes();cls.native=NativeSourceLexer(raw,sha256(raw).hexdigest())
        cls.manifest=cls.folder/'manifest.json'
        cls.manifest.write_text(json.dumps({'schema':'hepta.hia.source-lexer-native.v1',
            'source_sha256':sha256(SOURCE.read_bytes()).hexdigest(),'image_path':image.name,
            'image_sha256':sha256(raw).hexdigest(),
            'compiler_sha256':sha256(second.read_bytes()).hexdigest()}))

    @classmethod
    def tearDownClass(cls):cls.temporary.cleanup()

    def compare(self,source):
        self.assertEqual(outcome(self.native.tokenize,source),outcome(tokenize,source),repr(source[:160]))

    def test_all_keywords_operators_numeric_forms_and_source_positions(self):
        self.compare(' '.join(KEYWORD_ORDER)+' '+ ' '.join(PAIR_ORDER)+' {}()[],:;=+-*/%!<>.&|^')
        for source in ('ab/* x */cd','/* π🙂 */\r\n  fn f\r\n','\r\tfn',
                '// π🙂\rfn\n//x\nreturn',"'a '_x42",'"C" "中文🙂"',
                '0..8 1.5 2e-3 1_024 0xff 0b101 0o17','1.foo 1...3 0Xf_F 0O7_0 0B1_0',
                '0'*4096,'0x'+'f'*4094,'1e-999','\r\r\n\n fn'):
            with self.subTest(source=source[:80]):self.compare(source)
        self.assertEqual(self.receipt['forbidden_compiler_modules_loaded'],[])

    def test_diagnostic_code_message_and_exact_spans_match_reference(self):
        for source in ('#','@','`',"'",'$', 'π','\x00','\u00a0',
                '0x','0b102','0o9','12u32','1__2','1_','0x_ff','1e','1e+',
                '1e999','1.0f64','9'*5000,'"C\\x00"','"\\n"','"C','"C\n"',
                '"C\x00"','/* x /* nested */','1._0','0x1g',"'🙂",'"a\x1f"'):
            with self.subTest(source=source[:80]):
                self.compare(source);self.compare(' /* π🙂 */\r\n  '+source)

    def test_two_thousand_deterministic_random_token_and_comment_compositions(self):
        rng=random.Random(0x1e7e2026)
        fragments=list(KEYWORD_ORDER)+list(PAIR_ORDER)+list('{}()[],:;=+-*/%!<>.&|^')+[
            'abc','x_7',"'life",'0x7f','1_234','1.2e-3','/* π /* 内 */ 🙂 */',
            '// comment\r\n','"🙂C"',' ','\t','\r','\n','\r\n',
            '#','0x','1__2','0b2','"\\n"',"'",'/*','é']
        for _ in range(2000):self.compare(''.join(rng.choice(fragments) for _ in range(rng.randrange(1,24))))
        valid=list(KEYWORD_ORDER)+list(PAIR_ORDER)+['{}','()','[]','abc','x_7',
            "'life",'0x7f','1_234','1.2e-3','/* π /* 内 */ 🙂 */','"🙂C"']
        for _ in range(1000):self.compare(' '.join(rng.choice(valid) for _ in range(rng.randrange(1,32))))

    def test_all_Latin1_code_points_in_tokens_strings_and_nested_comments(self):
        for value in range(256):
            character=chr(value)
            for source in (character,'"'+character+'"','/* π '+character+' */\r\n fn'):
                self.compare(source)

    def test_actual_repository_source_corpus_not_only_synthetic_tokens(self):
        paths=sorted((ROOT/'tests').rglob('*.hepta'))+sorted((ROOT/'examples').rglob('*.hepta'))
        self.assertGreater(len(paths),50)
        for path in paths[:300]:
            source=path.read_text()
            with self.subTest(path=str(path.relative_to(ROOT))):self.compare(source)

    def test_native_scanner_does_not_call_reference_tokenizer_and_is_reentrant(self):
        sources=['/* '+chr(0x4e00+i)+' */\r\n fn f'+str(i)+'() {}' for i in range(64)]
        expected=[tokenize(s) for s in sources]
        with patch('hepta.lexer.Lexer.tokenize',side_effect=AssertionError('foreign token recognition')):
            with ThreadPoolExecutor(max_workers=8) as pool:
                self.assertEqual(list(pool.map(self.native.tokenize,sources)),expected)

    def test_direct_ABI_refusals_are_transactional_and_guards_unchanged(self):
        for wire,capacity,state_size,wanted in ((b'fn x',1,128,0xfffffffe),
                (b'fn x',224,127,0xfffffffd),(b'1__2',224,128,0xffffffff),
                (b'/*\xc0\x80*/',224,128,0xffffffff),
                (b'"\xed\xa0\x80"',224,128,0xffffffff),
                (b'"\xf4\x90\x80\x80"',224,128,0xffffffff)):
            source=ctypes.create_string_buffer(wire,len(wire))
            output=ctypes.create_string_buffer(b'\xa5'*(capacity+8),capacity+8)
            state=ctypes.create_string_buffer(b'\x5a'*(state_size+8),state_size+8)
            status=self.native._entry(source,len(wire),output,capacity,state,state_size)
            self.assertEqual(status,wanted)
            self.assertEqual(output.raw,b'\xa5'*(capacity+8))
            self.assertEqual(state.raw[state_size:],b'\x5a'*8)
            self.assertEqual(source.raw,wire)
        with self.assertRaises(ValueError):self.native.tokenize('/*\ud800*/')

    def test_operator_selected_token_API_and_real_parser_use_native_recognition(self):
        from hepta.parser import parse
        source='module demo; fn answer() -> i32 effects {} { return 42; }'
        expected=parse(source,'selected.hepta')
        error=outcome(tokenize,'/* π */\r\n0b102')
        with patch.dict('os.environ',{'HEPTA_HIA_SOURCE_LEXER_MANIFEST':str(self.manifest)}):
            with patch('hepta.lexer.Lexer.tokenize',side_effect=AssertionError('foreign token recognition')):
                self.assertEqual(parse(source,'selected.hepta'),expected)
                self.assertEqual(outcome(tokenize,'/* π */\r\n0b102'),error)
        # No global/default switch; scalar-Unicode is an explicit bounded
        # candidate profile, while the existing reference still accepts this.
        self.assertEqual(tokenize('/*\ud800*/')[-1].kind,'EOF')

    def test_exact_native_input_and_token_budgets(self):
        # A two-pass validation still admits the entire 8MiB comment. Only an
        # EOF row is needed; do not manufacture a huge output for this control.
        wire=b'//'+b'x'*((8<<20)-2)
        source=ctypes.create_string_buffer(wire,len(wire))
        output=ctypes.create_string_buffer(64);state=ctypes.create_string_buffer(136)
        output.raw=b'\xa5'*64;state.raw=b'\x5a'*136
        self.assertEqual(self.native._entry(source,len(wire),output,56,state,128),56)
        self.assertEqual(output.raw[56:],b'\xa5'*8)
        self.assertEqual(state.raw[128:],b'\x5a'*8)
        self.assertEqual(int.from_bytes(output.raw[8:16],'little'),8<<20)
        output.raw=b'\xa5'*64;state.raw=b'\x5a'*136
        self.assertEqual(self.native._entry(source,len(wire)+1,output,56,state,128),0xfffffffd)
        self.assertEqual(output.raw,b'\xa5'*64)
        self.assertEqual(state.raw,b'\x5a'*136)
        # Token cap includes EOF. Exact cap is admitted; one extra punctuation
        # refuses during the validation pass, before any output is written.
        count=(1<<20)-1
        source=ctypes.create_string_buffer(b'!'*(count+1),count+1)
        capacity=(1<<20)*56
        output=ctypes.create_string_buffer(capacity+8);state=ctypes.create_string_buffer(128)
        ctypes.memset(ctypes.addressof(output)+capacity,0xa5,8)
        self.assertEqual(self.native._entry(source,count,output,capacity,state,128),capacity)
        self.assertEqual(output.raw[capacity:],b'\xa5'*8)
        tiny=ctypes.create_string_buffer(b'\xa5'*64,64)
        self.assertEqual(self.native._entry(source,count+1,tiny,56,state,128),0xffffffff)
        self.assertEqual(tiny.raw,b'\xa5'*64)
        self.assertEqual(int.from_bytes(state.raw[48:56],'little'),12)

    def test_invalid_selected_manifest_refuses_without_reference_fallback(self):
        from hepta.hia_source_lexer_native import installed_source_lexer
        installed_source_lexer(str(self.manifest))  # Warm code cache first.
        changed=self.folder/'changed-source.hiaasm';changed.write_bytes(SOURCE.read_bytes()+b'\n')
        with patch.dict('os.environ',{'HEPTA_HIA_SOURCE_LEXER_MANIFEST':str(self.manifest)}):
            with patch('hepta.hia_source_lexer_native.SOURCE',changed):
                with self.assertRaisesRegex(ValueError,'source identity mismatch'):tokenize('fn f')
