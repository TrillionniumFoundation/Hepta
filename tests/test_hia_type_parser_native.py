"""Independent VM and real successors for the complete source type grammar."""
from __future__ import annotations
import ctypes
import json
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from pathlib import Path
import random
import struct
import tempfile
import unittest

from hepta.ast import HeptaError,Type
from hepta.parser import Parser
from hepta.hia_type_parser_native import NativeTypeParser,SOURCE,packet,materialize,WORKSPACE
from tools.generate_hia_type_parser import document
ROOT=Path(__file__).resolve().parents[1]


def observed(parser,call):
    try:result=('type',call(parser))
    except HeptaError as error:result=('error',error.diagnostic.to_dict())
    return result,parser.position,parser.tokens,parser.depth


def vm_references():
    from tests.test_hia_json_decode_native import vm_arena
    vm_exact_lifetime()
    for source,expected in [('Foo',Type('Foo')),('Buffer',None),('raw Foo',None)]:
        parser=Parser(source)
        code,raw=vm_arena(packet(parser.tokens),source_path=SOURCE,sizes=(240,WORKSPACE))
        assert code<=240 and raw is not None,(source,code)
        try:actual=materialize(raw,parser)
        except HeptaError:
            assert expected is None,source
        else:assert actual==expected,(source,actual)


def vm_exact_lifetime():
    from tools.hia_selfhost_bulk import Body
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import execute_program
    wire=packet(Parser("Foo<'a>").tokens)
    expected=struct.pack('<10Q',3,0,4,0,1,0,0,0,0,0)
    expected+=struct.pack('<8Q',0,0,2,0,3,0,0,0)
    expected+=struct.pack('<8Q',7,0,0,0,0,0,0,0)
    expected+=struct.pack('<8Q',8,2,0,0,0,0,0,0)
    body=Body(0);owners=[];views=[]
    for size,initial in ((len(wire),wire),(len(expected),b''),(WORKSPACE,b'')):
        owner=body.value('buffer','buffer.new',[body.const('usize',size)])
        view=body.value('mutbuf','borrow.mut',[owner])
        for i,value in enumerate(initial):
            if value:body.effect('buffer.store',[view,body.const('usize',i),body.const('u8',value)])
        owners.append(owner);views.append(view)
    body.effect('loan.end',[views[0]])
    views[0]=body.value('readbuf','borrow.read',[owners[0]])
    code=body.value('u32','call',views,{'function':'f0'})
    equal=body.value('bool','compare.eq',[code,body.const('u32',len(expected))])
    for i,value in enumerate(expected):
        actual=body.value('u8','buffer.load',[views[1],body.const('usize',i)])
        ok=body.value('bool','compare.eq',[actual,body.const('u8',value)])
        equal=body.value('bool','bool.and',[equal,ok])
    for view in views:body.effect('loan.end',[view])
    for owner in owners:body.effect('owner.drop',[owner])
    source=('hia-asm.v1 hepta.hia.program.v8 type_reference\n'
        'fn observe() -> (bool) effects(alloc,read,write,trap) entry(b0)\n'
        'block b0()\n'+body.text()+'  ret('+equal+')\nend\n'+SOURCE.read_text().split('\n',1)[1])
    actual=execute_program(assemble_program(source),'observe',[],max_steps=2000000)
    assert actual['status']=='returned' and actual['values']==[True],actual


class TypeParserSourceTests(unittest.TestCase):
    def test_generated_HIA_source_and_independent_VM_before_seed(self):
        from hepta.hia_agent_assembly import render_assembly
        self.assertEqual(render_assembly(document()),SOURCE.read_text())
        vm_references()


class TypeParserNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        vm_references()
        from tools.qualify_hia_selfhost import build_seed,compile_stage
        cls.temporary=tempfile.TemporaryDirectory(prefix='hia-type-parser-')
        cls.folder=Path(cls.temporary.name)
        seed,_=build_seed(cls.folder)
        compiler=(ROOT/'examples/hia_bootstrap/selfhost.hiaasm').read_bytes()
        first,_=compile_stage(cls.folder,'B1',seed,compiler,image_format='seed-shared')
        second,_=compile_stage(cls.folder,'B2',first,compiler)
        assert first.read_bytes()==second.read_bytes()
        image,cls.receipt=compile_stage(cls.folder,'type-parser',second,SOURCE.read_bytes())
        raw=image.read_bytes();cls.native=NativeTypeParser(raw,sha256(raw).hexdigest())
        cls.manifest=cls.folder/'type-manifest.json'
        cls.manifest.write_text(json.dumps({'schema':'hepta.hia.type-parser-native.v1',
            'source_sha256':sha256(SOURCE.read_bytes()).hexdigest(),'image_path':image.name,
            'image_sha256':sha256(raw).hexdigest(),'compiler_sha256':sha256(second.read_bytes()).hexdigest()}))
        from hepta.hia_source_lexer_native import SOURCE as LEXER_SOURCE
        lexer_image,_=compile_stage(cls.folder,'source-lexer',second,LEXER_SOURCE.read_bytes())
        cls.lexer_manifest=cls.folder/'lexer-manifest.json'
        cls.lexer_manifest.write_text(json.dumps({'schema':'hepta.hia.source-lexer-native.v3',
            'source_sha256':sha256(LEXER_SOURCE.read_bytes()).hexdigest(),'image_path':lexer_image.name,
            'image_sha256':sha256(lexer_image.read_bytes()).hexdigest(),'compiler_sha256':sha256(second.read_bytes()).hexdigest()}))
    @classmethod
    def tearDownClass(cls):cls.temporary.cleanup()
    def compare(self,source,depth=0):
        a=Parser(source,'type.hepta');b=Parser(source,'type.hepta');a.depth=b.depth=depth
        self.assertEqual(observed(a,lambda p:p._type()),observed(b,self.native.parse_type),source[:180])
    def test_all_grammar_paths_and_exact_errors(self):
        for source in ('u64','foo /* π */ :: Bar','Buffer<u8>','Task<Result<u8,E>>',
            "read 'a mut 'b raw const [Foo<'a, u8, 'b, [Bar;0x123]>;0b10]",
            'Sender<raw mut T>','m::Buffer','Buffer','Buffer<>','Task<T,U>',
            'Foo<T,>','Foo<T U>','Foo<','Foo<T>=1','Foo<Foo<T>>=1',
            'Foo<Foo<Foo<T>>>','[]','[T; -1]','[T; 1.5]','[T; 0xffff]',
            '[T','raw T','read T','mut T','foo::','fn','Foo<\'a, T, \'b, U>',
            'Foo<T>>','Foo<T>=','::Foo','[T;'+('9'*4096)+']'):
            with self.subTest(source=source[:120]):self.compare(source)
    def test_existing_nesting_boundary_and_outer_depth(self):
        for depth in (0,1,40,94,95,96):
            for n in (0,1,max(0,95-depth),max(0,96-depth),97):
                self.compare('raw const '*n+'T',depth)
                self.compare('Box<'*n+'T'+'>'*n,depth)
    def test_deterministic_generated_recursive_grammar_and_invalid_mutations(self):
        rng=random.Random(0x7a1e2026)
        def ty(depth):
            if depth<=0:return rng.choice(['T','m::T','u64'])
            child=lambda:ty(depth-1)
            return rng.choice([lambda:'raw const '+child(),lambda:"read 'a "+child(),
                lambda:'['+child()+']',lambda:'['+child()+';0x1_f]',
                lambda:'Pair<'+child()+", 'a, "+child()+'>',lambda:'Buffer<'+child()+'>'])()
        for _ in range(250):
            source=ty(rng.randrange(5));self.compare(source)
            self.compare(source[:-1]);self.compare(source.replace('>', '>=',1))
    def test_refusal_buffers_are_transactional_and_private_calls_reentrant(self):
        wire=packet(Parser('Foo<Bar<T>>').tokens)
        for data,capacity,work,wanted in ((wire,1,WORKSPACE,0xfffffffe),(wire,4096,WORKSPACE-1,0xfffffffd),
            (wire[:47],4096,WORKSPACE,0xfffffffd),(b'BADMAGIC'+wire[8:],4096,WORKSPACE,0xfffffffd)):
            s=ctypes.create_string_buffer(data,len(data));o=ctypes.create_string_buffer(b'\xa5'*(capacity+8),capacity+8)
            w=ctypes.create_string_buffer(b'\x5a'*(work+8),work+8)
            self.assertEqual(self.native._entry(s,len(data),o,capacity,w,work),wanted)
            self.assertEqual(o.raw,b'\xa5'*(capacity+8));self.assertEqual(w.raw[work:],b'\x5a'*8)
            self.assertEqual(s.raw,data)
        sources=['Box<raw const [T;'+str(i)+']>' for i in range(32)]
        with ThreadPoolExecutor(max_workers=8) as pool:
            actual=list(pool.map(lambda s:self.native.parse_type(Parser(s)),sources))
        self.assertEqual(actual,[Parser(s)._type() for s in sources])

    def test_real_parser_callers_with_foreign_type_grammar_disabled_and_both_lexers(self):
        from hepta.parser import parse
        sources=["module demo; struct Pair<'a, T> { value: read 'a T, next: raw mut Pair<'a,T> } "
            "enum Maybe<T> { Some(T), None } fn f(x: [u8;16]) -> Buffer<u8> effects {} { "
            "let p: raw const u8; return x; }",
            'fn f(x: Box<Box<u64>>) -> u64 effects {} { let x: Box<u8>=v; return 0; }']
        paths=sorted((ROOT/'tests').rglob('*.hepta'))+sorted((ROOT/'examples').rglob('*.hepta'))
        sources += [p.read_text() for p in paths[:300]]
        def result(source):
            try:return ('program',parse(source,'native-type.hepta'))
            except HeptaError as error:return ('error',error.diagnostic.to_dict())
        reference=[result(source) for source in sources]
        for lexer in ('',str(self.lexer_manifest)):
            with patch.dict('os.environ',{'HEPTA_HIA_TYPE_PARSER_MANIFEST':str(self.manifest),
                    'HEPTA_HIA_SOURCE_LEXER_MANIFEST':lexer}):
                with patch.object(Parser,'_type_reference',side_effect=AssertionError('foreign type grammar')):
                    if lexer:
                        with patch('hepta.lexer.Lexer.tokenize',side_effect=AssertionError('foreign token recognition')):
                            actual=[result(source) for source in sources]
                    else:actual=[result(source) for source in sources]
            self.assertEqual(actual,reference)

    def test_selected_identity_failure_is_not_a_grammar_fallback(self):
        with patch.dict('os.environ',{'HEPTA_HIA_TYPE_PARSER_MANIFEST':str(self.manifest)}):
            self.assertEqual(Parser('T')._type(),Type('T'))
            changed=self.folder/'changed-type.hiaasm';changed.write_bytes(SOURCE.read_bytes()+b'\n')
            with patch('hepta.hia_type_parser_native.SOURCE',changed):
                with self.assertRaisesRegex(ValueError,'source identity mismatch'):Parser('T')._type()
        with patch.dict('os.environ',{'HEPTA_HIA_TYPE_PARSER_MANIFEST':str(self.manifest)}):
            # An explicitly out-of-profile token collection keeps original behavior.
            p=Parser('T '+(';'*4096))
            self.assertEqual(p._type(),Type('T'))
