"""Independent source lexing, real HIA successors, spans and refusals."""
from __future__ import annotations
import ctypes
import json
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from pathlib import Path
import random
import struct
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
        assert materialize(source,'<input>',wire,raw,lambda literal:{b'0x3f':63}[literal],lambda literal:{}[literal])==tokenize(source),source
    code,_=vm_arena(b'1__2',source_path=SOURCE,sizes=(224,128))
    assert code==0xffffffff
    # Exercise command mode 1 in the independent VM before any native seed.
    for wire,expected in ((b'0',b'\0'),(b'255',b'\xff'),(b'256',b'\0\1'),
                          (b'0x1_0000',b'\0\0\1'),(b'0b110000000',b'\x80\1'),
                          (b'0o777',b'\xff\1'),(b'0x_ff',None),(b'1_',None)):
        code,raw=vm_integer(wire)
        if expected is None:assert code==0xffffffff
        else:assert code==len(expected) and raw==expected,(wire,code,raw)
    # Binary64 bits are independent literal expectations, not a host parser.
    for wire,wanted in ((b'0.0',bytes(8)),(b'0.5',bytes.fromhex('000000000000e03f')),
                        (b'1.25',bytes.fromhex('000000000000f43f')),
                        (b'1.00000000000000011102230246251565404236316680908203125',bytes.fromhex('000000000000f03f'))):
        code,raw=vm_integer(wire,mode=2,workspace=6272)
        assert code==8 and raw==wanted,(wire,code,raw)
    assert vm_integer(b'1e999',mode=2,workspace=6272)[0]==0xfffffffc
    assert vm_integer(b'1.0_',mode=2,workspace=6272)[0]==0xffffffff


def vm_integer(wire,mode=1,workspace=2176):
    from tools.hia_selfhost_bulk import Body
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import execute_program
    body=Body(0);owners=[];views=[]
    state=bytearray(workspace);struct.pack_into('<Q',state,120,mode)
    for size,initial in ((len(wire),wire),(8,b''),(workspace,state)):
        owner=body.value('buffer','buffer.new',[body.const('usize',size)])
        view=body.value('mutbuf','borrow.mut',[owner])
        for i,value in enumerate(initial):
            if value:body.effect('buffer.store',[view,body.const('usize',i),body.const('u8',value)])
        owners.append(owner);views.append(view)
    body.effect('loan.end',[views[0]])
    views[0]=body.value('readbuf','borrow.read',[owners[0]])
    code=body.value('u32','call',views,{'function':'f0'})
    raw=[body.value('u8','buffer.load',[views[1],body.const('usize',i)]) for i in range(8)]
    for view in views:body.effect('loan.end',[view])
    for owner in owners:body.effect('owner.drop',[owner])
    source=('hia-asm.v1 hepta.hia.program.v8 integer_reference\n'
            'fn observe() -> (u32,'+','.join(['u8']*8)+') effects(alloc,read,write,trap) entry(b0)\n'
            'block b0()\n'+body.text()+'  ret('+','.join([code,*raw])+')\nend\n'
            +SOURCE.read_text().split('\n',1)[1])
    actual=execute_program(assemble_program(source),'observe',[],max_steps=2000000)
    assert actual['status']=='returned',actual
    code,*raw=actual['values']
    return code,bytes(raw[:code]) if code<=8 else None


class SourceLexerSourceTests(unittest.TestCase):
    def test_checked_in_source_and_keyword_protocol_are_exact(self):
        from hepta.hia_agent_assembly import render_assembly,assemble_program
        self.assertEqual(render_assembly(document()),SOURCE.read_text())
        self.assertEqual(frozenset(KEYWORD_ORDER),KEYWORDS)
        self.assertEqual(len(assemble_program(SOURCE.read_bytes()).as_dict()['functions']),30)
        from tools.hia_selfhost_contract import support_contract
        profile=support_contract()
        self.assertEqual(profile['source_lexer_application']['maximum_tokens_including_EOF'],1<<20)
        self.assertEqual(profile['source_lexer_application']['workspace_bytes'],128)
        self.assertEqual(profile['source_lexer_application']['integer_workspace_bytes'],2176)
        self.assertEqual(profile['source_lexer_application']['integer_magnitude_capacity_bytes'],2048)
        self.assertEqual(profile['source_lexer_application']['float_workspace_bytes'],6272)
        self.assertNotIn('high_level_source_lexing',[row['area'] for row in profile['support']])


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
        cls.manifest.write_text(json.dumps({'schema':'hepta.hia.source-lexer-native.v3',
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

    def test_earlier_float_errors_precede_later_lexical_errors_without_host_parsing(self):
        from hepta.lexer import Lexer
        from types import SimpleNamespace
        suffixes=(' @',' /* unclosed',' 1__2',' "C\\x00"',' "C\n"',
                  " '",' π',' 0x',' "unfinished')
        literals=('1e9999','1.7976931348623159e308','1e9999 0.5',
                  '0.5 1e9999','1e-9999 0e99999','1e9999x')
        sources=[prefix+literal+suffix
                 for prefix in ('','/* π🙂 */\r\n\t','fn f() -> u32 effects {} { return ')
                 for literal in literals for suffix in suffixes]
        sources += ['@ 1e9999','1__2 1e9999','"\\n" 1e9999',
                    '1e9999_ @','1e9999x @','9'*4096+'.0 @']
        expected=[outcome(lambda source,path:Lexer(source,path).tokenize(),source)
                  for source in sources]
        with patch('hepta.hia_source_lexer_native.int',SimpleNamespace(from_bytes=int.from_bytes),create=True):
            with patch('hepta.hia_source_lexer_native.float',SimpleNamespace(),create=True):
                with patch('hepta.lexer.Lexer.tokenize',side_effect=AssertionError('foreign tokenizer')):
                    for source,wanted in zip(sources,expected):
                        with self.subTest(source=source[:96]):
                            self.assertEqual(outcome(self.native.tokenize,source),wanted)
                    with ThreadPoolExecutor(max_workers=8) as pool:
                        actual=list(pool.map(lambda source:outcome(self.native.tokenize,source),sources))
                    self.assertEqual(actual,expected)

    def test_float_error_replay_is_bounded_at_the_exact_token_cap(self):
        count=(1<<20)-1
        cases=(('!'*count+'1e9999 @','E_LEX_NUMBER',count,count+6),
               ('!'*count+'0.5 @','E_LEX_CHARACTER',count+4,count+5),
               ('1e9999 '+'!'*(count+1),'E_LEX_NUMBER',0,6))
        for source,code,start,end in cases:
            with self.subTest(code=code,start=start):
                with patch.object(self.native,'_tokenize',wraps=self.native._tokenize) as replay:
                    actual=outcome(self.native.tokenize,source)
                self.assertEqual(actual[0],'diagnostic')
                self.assertEqual(actual[1]['code'],code)
                self.assertEqual(actual[1]['span'],{'path':'lexical-input.hepta',
                    'start':start,'end':end,'line':1,'column':start+1})
                self.assertEqual(replay.call_count,2)
                self.assertEqual([call.kwargs['check_earlier_float'] for call in replay.call_args_list],
                                 [True,False])
        # Even inconsistent image metadata cannot trigger a recursive replay.
        def bad_prefix(source,size,output,capacity,state,workspace):
            struct.pack_into('<Q',state,48,10)
            struct.pack_into('<Q',state,56,7)
            struct.pack_into('<2Q',state,88,0,6)
            return 0xffffffff
        with patch.object(self.native,'_entry',side_effect=bad_prefix) as calls:
            with self.assertRaisesRegex(RuntimeError,'float replay prefix was not admitted'):
                self.native.tokenize('1e9999 @')
        self.assertEqual(calls.call_count,2)

    def test_failed_scan_preserves_native_float_range_without_publishing_output(self):
        cases=((b'@',(0,0)),(b'1e9999 @',(0,6)),
               (b'1e9999 0.5 /* unfinished',(7,10)),
               (b'1.0 "C\\x00"',(0,3)),(b'1.0 "C\n"',(0,3)),
               (b'1.0 1__2',(0,3)),('1.0 π'.encode(),(0,3)),
               ('/* π🙂 */\r\n1e9999 "unfinished'.encode(),(14,20)))
        for wire,wanted in cases:
            with self.subTest(wire=wire):
                source=ctypes.create_string_buffer(wire,len(wire))
                output=ctypes.create_string_buffer(b'\xa5'*232,232)
                state=ctypes.create_string_buffer(b'\x5a'*136,136)
                struct.pack_into('<Q',state,120,0)
                self.assertEqual(self.native._entry(source,len(wire),output,224,state,128),0xffffffff)
                self.assertEqual(struct.unpack_from('<2Q',state,88),wanted)
                self.assertEqual(output.raw,b'\xa5'*232)
                self.assertEqual(state.raw[128:],b'\x5a'*8)
                self.assertEqual(source.raw,wire)

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
            if state_size>=128:struct.pack_into('<Q',state,120,0)
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
        with patch.dict('os.environ',{'HEPTA_HIA_SOURCE_LEXER_MANIFEST':str(self.manifest)}):
            self.assertEqual(tokenize('/*\ud800*/')[-1].kind,'EOF')

    def test_exact_native_input_and_token_budgets(self):
        # A two-pass validation still admits the entire 8MiB comment. Only an
        # EOF row is needed; do not manufacture a huge output for this control.
        wire=b'//'+b'x'*((8<<20)-2)
        source=ctypes.create_string_buffer(wire,len(wire))
        output=ctypes.create_string_buffer(64);state=ctypes.create_string_buffer(136)
        output.raw=b'\xa5'*64;state.raw=b'\x5a'*136
        struct.pack_into('<Q',state,120,0)
        self.assertEqual(self.native._entry(source,len(wire),output,56,state,128),56)
        self.assertEqual(output.raw[56:],b'\xa5'*8)
        self.assertEqual(state.raw[128:],b'\x5a'*8)
        self.assertEqual(int.from_bytes(output.raw[8:16],'little'),8<<20)
        output.raw=b'\xa5'*64;state.raw=b'\x5a'*136
        struct.pack_into('<Q',state,120,0)
        self.assertEqual(self.native._entry(source,len(wire)+1,output,56,state,128),0xfffffffd)
        self.assertEqual(output.raw,b'\xa5'*64)
        self.assertEqual(state.raw,b'\x5a'*120+b'\0'*8+b'\x5a'*8)
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

    def test_arbitrary_integer_values_all_bases_separators_and_exact_lengths(self):
        rng=random.Random(0x1e7e123)
        for bits in (0,1,7,8,9,15,16,63,64,65,127,128,1024,4096,8192,13000):
            for base,prefix,format_code in ((10,'','d'),(16,'0x','x'),(8,'0o','o'),(2,'0b','b')):
                for _ in range(4):
                    expected=rng.getrandbits(bits);digits=format(expected,format_code)
                    if len(prefix)+len(digits)>4096:continue
                    for source in (prefix+digits,prefix+'_'.join(digits)):
                        with self.subTest(bits=bits,base=base,length=len(source)):
                            self.assertEqual(self.native.integer_value(source.encode()),expected)
                            self.compare(source)
        for source,base in (('9'*4096,10),('0x'+'f'*4094,16),
                            ('0b'+'1'*4094,2),('0o'+'7'*4094,8),
                            ('_'.join('9'*4096),10)):
            self.assertEqual(self.native.integer_value(source.encode()),int(source.replace('_',''),base))
            self.compare(source)

    def test_integer_command_transactional_refusals_and_exact_scratch_guards(self):
        cases=[(s,2048,2176,1,0xffffffff) for s in
               (b'',b'_1',b'1_',b'1__2',b'0x_ff',b'0x',b'-1',b'0b2',b'0o8',
                b'1e2',b'9'*4097,b'\xff',b'123\x00',b' 1')]
        cases += [(b'256',1,2176,1,0xfffffffe),(b'1',0,2176,1,0xfffffffe),
                  (b'1',2048,2175,1,0xfffffffd),(b'1'*8193,2048,2176,1,0xfffffffd),
                  (b'fn',224,128,3,0xfffffffd)]
        for wire,capacity,state_size,mode,wanted in cases:
            with self.subTest(wire=wire[:20],mode=mode,capacity=capacity,state_size=state_size):
                source=ctypes.create_string_buffer(wire,max(1,len(wire)))
                output=ctypes.create_string_buffer(b'\xa5'*(capacity+8),capacity+8)
                state=ctypes.create_string_buffer(b'\x5a'*(state_size+8),state_size+8)
                struct.pack_into('<Q',state,120,mode)
                original_state=state.raw
                status=self.native._entry(source,len(wire),output,capacity,state,state_size)
                self.assertEqual(status,wanted)
                self.assertEqual(output.raw,b'\xa5'*(capacity+8))
                self.assertEqual(state.raw[state_size:],b'\x5a'*8)
                self.assertEqual(source.raw[:len(wire)],wire)
                if wanted in (0xfffffffd,0xffffffff):self.assertEqual(state.raw,original_state)
        with self.assertRaises(ValueError):self.native.integer_value(b'0x_ff')

    def test_selected_integer_parser_uses_no_host_literal_conversion(self):
        from types import SimpleNamespace
        source='0 255 0x10000000000000000 0b1_0 0o7_7 '+('9'*4096)
        expected=tokenize(source)
        # Only int.from_bytes (object construction) is available in this module.
        with patch('hepta.hia_source_lexer_native.int',SimpleNamespace(from_bytes=int.from_bytes),create=True):
            with patch('hepta.lexer.Lexer.tokenize',side_effect=AssertionError('foreign tokenizer')):
                self.assertEqual(self.native.tokenize(source),expected)
                with ThreadPoolExecutor(max_workers=8) as pool:
                    self.assertEqual(list(pool.map(self.native.tokenize,[source]*16)),[expected]*16)

    def test_old_manifests_are_not_accepted_for_changed_workspace_command_protocol(self):
        from hepta.hia_source_lexer_native import installed_source_lexer
        old=self.folder/'old-manifest.json'
        manifest=json.loads(self.manifest.read_text())
        for version in (1,2):
            manifest['schema']='hepta.hia.source-lexer-native.v'+str(version)
            old.write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):installed_source_lexer(str(old))

    def test_binary64_rounding_normal_subnormal_halfway_and_overflow_boundaries(self):
        import math
        cases=['0.0','1.0','0.1','0.5','1.25','2e308','1.7976931348623157e308',
            '1.7976931348623158e308','1.7976931348623159e308','2.2250738585072014e-308',
            '2.225073858507201e-308','5e-324','4.9406564584124654e-324','2.4703282292062327e-324',
            '2.4703282292062328e-324','1e-324','0e99999','0.0e-99999','1e99999','1e-99999',
            '1.00000000000000011102230246251565404236316680908203125',
            '1.00000000000000033306690738754696212708950042724609375',
            '9'*4000+'.0e-3999','0.'+'0'*4000+'1e4000','0.'+'9'*4000+'e-308',
            '1_234.5_6e-0_1','0.'+'0'*4092+'1']
        rng=random.Random(0xf1064)
        for _ in range(1500):
            digits=str(rng.randrange(1,10))+''.join(str(rng.randrange(10)) for _ in range(rng.randrange(0,140)))
            middle=rng.randrange(1,len(digits)+1)
            cases.append(digits[:middle]+'.'+(digits[middle:] or '0')+'e'+str(rng.randrange(-500,400)))
        for literal in cases:
            with self.subTest(source=literal[:80]):
                expected=float(literal.replace('_',''))
                if math.isfinite(expected):
                    self.assertEqual(struct.pack('<d',self.native.float_value(literal.encode())),struct.pack('<d',expected))
                else:
                    with self.assertRaises(OverflowError):self.native.float_value(literal.encode())
                self.compare(literal)

    def test_float_command_refusals_are_transactional_with_exact_guards(self):
        cases=[(s,8,6272,0xffffffff) for s in
               (b'',b'1',b'1.',b'.1',b'1e',b'1e+',b'0x1.2',b'1__2.0',b'1._0',b'1.0_',
                b'NaN',b'inf',b'-1.0',b'1.0x',b'9'*4096+b'.0',b'1.0\x00')]
        cases += [(b'2e308',8,6272,0xfffffffc),(b'1.0',7,6272,0xfffffffe),
                  (b'1.0',8,6271,0xfffffffd),(b'1.'+b'0'*8191,8,6272,0xfffffffd)]
        for wire,capacity,state_size,wanted in cases:
            with self.subTest(wire=wire[:20],capacity=capacity,state_size=state_size):
                source=ctypes.create_string_buffer(wire,max(1,len(wire)))
                output=ctypes.create_string_buffer(b'\xa5'*(capacity+8),capacity+8)
                state=ctypes.create_string_buffer(b'\x5a'*(state_size+8),state_size+8)
                struct.pack_into('<Q',state,120,2)
                self.assertEqual(self.native._entry(source,len(wire),output,capacity,state,state_size),wanted)
                self.assertEqual(output.raw,b'\xa5'*(capacity+8))
                self.assertEqual(state.raw[state_size:],b'\x5a'*8)
                self.assertEqual(source.raw[:len(wire)],wire)

    def test_all_numeric_values_without_host_literal_parsers_and_private_concurrency(self):
        from types import SimpleNamespace
        source='0x10000000000000000 1.25 0.1 5e-324 1e-9999 1_024.5_0'
        expected=tokenize(source)
        with patch('hepta.hia_source_lexer_native.int',SimpleNamespace(from_bytes=int.from_bytes),create=True):
            with patch('hepta.hia_source_lexer_native.float',SimpleNamespace(),create=True):
                with patch('hepta.lexer.Lexer.tokenize',side_effect=AssertionError('foreign tokenizer')):
                    with ThreadPoolExecutor(max_workers=8) as pool:
                        self.assertEqual(list(pool.map(self.native.tokenize,[source]*32)),[expected]*32)
