"""Whole-program source grammar: independent VM, real successors and AST parity."""
from __future__ import annotations
import ast
import ctypes
import json
import os
import random
from hashlib import sha256
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
from hepta.ast import HeptaError
from hepta.parser import Parser
from hepta.hia_source_parser_native import NativeSourceParser,Arena,SOURCE,WORKSPACE,packet
from tools.generate_hia_source_parser import document,source_program
ROOT=Path(__file__).resolve().parents[1]


def observed(source,call,depth=0):
    p=None
    try:
        p=Parser(source,'whole.hepta');p.depth=depth;result=('program',call(p))
    except HeptaError as e:result=('error',e.diagnostic.to_dict())
    return (result,p.position,p.tokens,p.qualified_expressions,p.depth) if p else (result,)


def vm_arena(source,depth=0):
    from tools.hia_selfhost_bulk import Body
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import execute_program
    p=Parser(source);p.depth=depth;wire=packet(p);body=Body(0);owners=[];views=[]
    for size,initial in ((len(wire),wire),(1920,b''),(WORKSPACE,b'')):
        owner=body.value('buffer','buffer.new',[body.const('usize',size)])
        view=body.value('mutbuf','borrow.mut',[owner])
        for i,value in enumerate(initial):
            if value:body.effect('buffer.store',[view,body.const('usize',i),body.const('u8',value)])
        owners.append(owner);views.append(view)
    body.effect('loan.end',[views[0]])
    views[0]=body.value('readbuf','borrow.read',[owners[0]])
    code=body.value('u32','call',views,{'function':'f0'})
    names={n.name:'f'+str(i) for i,n in enumerate(ast.parse(source_program()).body)}
    words=[body.value('u64','call',[views[1],body.const('u64',8*i)],{'function':names['get']}) for i in range(240)]
    for v in views:body.effect('loan.end',[v])
    for o in owners:body.effect('owner.drop',[o])
    source=('hia-asm.v1 hepta.hia.program.v8 full_parser_reference\n'
        'fn observe() -> (u32,'+','.join(['u64']*240)+') effects(alloc,read,write,trap) entry(b0)\n'
        'block b0()\n'+body.text()+'  ret('+','.join([code,*words])+')\nend\n'
        +SOURCE.read_text().split('\n',1)[1])
    actual=execute_program(assemble_program(source),'observe',[],max_steps=4000000)
    assert actual['status']=='returned',actual
    size,*words=actual['values'];assert size<=1920,(size,source[:80])
    return b''.join(struct.pack('<Q',v) for v in words)[:size]


def vm_references():
    for text,depth in (('',0),('module m;',0),('fn f() -> u8 effects {} {return 1;}',0),
                       ('extern "X" fn f() -> u8 effects {};',0),('fn f() -> u8 effects {} {}',96)):
        raw=vm_arena(text,depth)
        def run(p):
            a=Arena(raw,p);return a.build(a.root)
        assert observed(text,run,depth)==observed(text,lambda p:p.parse(),depth),text
    # A literal byte expectation independently checks the word/byte transport.
    raw=vm_arena('')
    expected=struct.pack('<16Q',3549479791681612105,1,0,0,0,1,0,0,0,0,0,0,0,0,0,0)
    expected+=struct.pack('<16Q',20,*([0]*15))
    assert raw==expected


class SourceParserSourceTests(unittest.TestCase):
    def test_generated_source_and_independent_VM_before_seed(self):
        from hepta.hia_agent_assembly import render_assembly
        self.assertEqual(render_assembly(document()),SOURCE.read_text())
        vm_references()


class SourceParserNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        vm_references()
        from tests.test_hia_source_lexer_native import vm_references as lexer_vm_references
        lexer_vm_references()
        from tools.qualify_hia_selfhost import build_seed,compile_stage
        cls.temporary=tempfile.TemporaryDirectory(prefix='hia-source-parser-')
        cls.folder=Path(cls.temporary.name);seed,_=build_seed(cls.folder)
        compiler=(ROOT/'examples/hia_bootstrap/selfhost.hiaasm').read_bytes()
        first,_=compile_stage(cls.folder,'B1',seed,compiler,image_format='seed-shared')
        second,_=compile_stage(cls.folder,'B2',first,compiler)
        assert first.read_bytes()==second.read_bytes()
        image,cls.receipt=compile_stage(cls.folder,'source-parser',second,SOURCE.read_bytes())
        raw=image.read_bytes();cls.native=NativeSourceParser(raw,sha256(raw).hexdigest())
        cls.manifest=cls.folder/'manifest.json'
        cls.manifest.write_text(json.dumps({'schema':'hepta.hia.source-parser-native.v1',
            'source_sha256':sha256(SOURCE.read_bytes()).hexdigest(),
            'image_path':image.name,'image_sha256':sha256(raw).hexdigest(),
            'compiler_sha256':sha256(second.read_bytes()).hexdigest()}))
        from hepta.hia_source_lexer_native import SOURCE as LEXER_SOURCE
        lex_image,_=compile_stage(cls.folder,'source-lexer',second,LEXER_SOURCE.read_bytes())
        cls.lexer_manifest=cls.folder/'lexer-manifest.json'
        cls.lexer_manifest.write_text(json.dumps({'schema':'hepta.hia.source-lexer-native.v3',
            'source_sha256':sha256(LEXER_SOURCE.read_bytes()).hexdigest(),
            'image_path':lex_image.name,'image_sha256':sha256(lex_image.read_bytes()).hexdigest(),
            'compiler_sha256':sha256(second.read_bytes()).hexdigest()}))
    @classmethod
    def tearDownClass(cls):cls.temporary.cleanup()
    def compare(self,source,depth=0):
        self.assertEqual(observed(source,self.native.parse,depth),observed(source,lambda p:p.parse(),depth),source[:200])
    def test_all_declarations_and_control_flow(self):
        cases=['','module m::n; import x::y; import z as zz;',
            'pub repr(C) struct P<T> { x:T, match:raw const T } enum E<T>{A, B(T)}',
            'extern "C" fn f<T:Owned>(x: take T) -> T effects {alloc};',
            "fn f<'a,T>(x: read 'a T) -> read 'a T from x effects {read} resources {n=8; p=1.5; ok=true;} { return x; }",
            'export "C" fn f()->u8 effects {} {let mut x: u8=1; x=2; x; return;}',
            'fn f()->u8 effects {} { for i in 0..8 {while i<8 {if i==4 {} else {} } } unsafe {} return 1;}',
            'enum E{A, B(u8)} fn f(x:E)->u8 effects {} {match x {E::A=>{return 0;},E::B(a)=>{return a;},} return 1;}',
            'fn f()->u8 effects {} {return (1+2)*3-4/2%2 << 1 & 7 | 2 ^ 1;}',
            'struct P {match:u8} fn f()->u8 effects {} {let p=P{match:1,}; p.match=2; return [1,2,][0] as u8;}',
            'struct P<T>{x:T} fn f()->u8 effects {} {return P::<u8>{x:f::<u8>(1)}.x;}',
            'fn f()->u8 effects {} {return unknown::f();}',
            'fn f()->u8 effects {} {return true || false && !false;}',
            'fn f()->Buffer<u8> effects {} {return g::<Buffer<Buffer<u8>>>();}',
            'fn f()->u8 effects {} {let p:Box<u8>=v; return 0;}',
            'fn f()->u8 effects {} { (f)(1); return read mut move x; }']
        for s in cases:
            with self.subTest(source=s):self.compare(s)
    def test_real_repository_syntax_corpus(self):
        paths=sorted((ROOT/'tests').rglob('*.hepta'))+sorted((ROOT/'examples').rglob('*.hepta'))
        for p in paths[:300]:
            with self.subTest(path=str(p.relative_to(ROOT))):self.compare(p.read_text())

    def test_mutations_preserve_first_error_cursor_tokens_and_spans(self):
        rng=random.Random(814920)
        sources=[
            'module a::b; import m::n as q; pub repr(C) struct P<T>{x:T,match:u8} enum E<T>{A,B(T)}',
            "fn f<'a,T:Owned>(x:read 'a T)->read 'a T from x effects {read,write} resources {n=8;} {return x;}",
            'fn f()->u8 effects {} {let mut x:Box<Buffer<u8>>=v; if x.a[0]>1 {return g::<u8>(x);} else {return 0;}}',
            'enum E{A,B(u8)} fn f(x:E)->u8 effects {} {match x {E::A=>{return 0;},E::B(a)=>{return a;},}}',
            'fn f()->u8 effects {} {for i in 0..8 {while i<8 {unsafe {p.match=2;}}} return P{x:[1,2,][0]}.x as u8;}',
        ]
        fragments=['', ' ', '::', '<', '>>', '>=', ',', ';', '{', '}', '(', ')', 'match', 'return', '"C"', "'a", '0', '1.5', 'true', 'pub']
        for i in range(1500):
            source=rng.choice(sources);a=rng.randrange(len(source)+1);b=min(len(source),a+rng.randrange(5))
            changed=source[:a]+rng.choice(fragments)+source[b:]
            with self.subTest(case=i,source=changed):self.compare(changed)

    def test_depth_bounds_and_iterative_left_chain(self):
        for n in (1,45,90,92,93,94,95,96,97,120,180):
            for expr in ('('*n+'1'+')'*n,'-'*n+'1','+'.join(['1']*n),'a'+'.x'*n):
                with self.subTest(n=n,expr=expr[:25]):self.compare('fn f()->u8 effects {} {return '+expr+';}')
            with self.subTest(blocks=n):self.compare('fn f()->u8 effects {} {'+'unsafe {'*n+'}'*n+'}')
            with self.subTest(types=n):self.compare('fn f()->'+'Box<'*n+'u8'+'>'*n+' effects {} {}')
        for depth in (0,1,94,95,96):
            self.compare('fn f()->u8 effects {} {return g::<Buffer<Buffer<u8>>>();}',depth)

    def test_private_reentrant_output_and_refusal_canaries(self):
        from concurrent.futures import ThreadPoolExecutor
        source='fn f()->u8 effects {} {return g::<Buffer<Buffer<u8>>>();}'
        wire=packet(Parser(source));inputs=ctypes.create_string_buffer(wire,len(wire))
        def raw_call(capacity,workspace,blob=wire):
            src=ctypes.create_string_buffer(blob,len(blob))
            out=ctypes.create_string_buffer(b'\xa5'*(capacity+64),capacity+64)
            work=ctypes.create_string_buffer(b'\x5a'*(workspace+64),workspace+64)
            size=self.native._entry(src,len(blob),ctypes.byref(out,32),capacity,ctypes.byref(work,32),workspace)
            self.assertEqual(out.raw[:32]+out.raw[-32:],b'\xa5'*64)
            self.assertEqual(work.raw[:32]+work.raw[-32:],b'\x5a'*64)
            self.assertEqual(src.raw,blob)
            return size,out.raw[32:-32],work.raw[32:-32]
        size,result,_=raw_call(32768,WORKSPACE)
        self.assertGreater(size,128)
        again=raw_call(size,WORKSPACE)
        self.assertEqual(again[0],size);self.assertEqual(again[1],result[:size])
        for capacity,workspace,blob,code in (
                (size-1,WORKSPACE,wire,0xfffffffe),(0,WORKSPACE,wire,0xfffffffe),
                (size,WORKSPACE-1,wire,0xfffffffd),(size,WORKSPACE,b'',0xfffffffd),
                (size,WORKSPACE,b'X'+wire[1:],0xfffffffd)):
            actual,out,work=raw_call(capacity,workspace,blob)
            self.assertEqual(actual,code);self.assertEqual(out,b'\xa5'*capacity)
        def parallel(i):
            text=source if i%2 else 'module m; struct P{x:u8} fn f()->u8 effects {} {return P{x:1}.x;}'
            return observed(text,self.native.parse)==observed(text,lambda p:p.parse())
        with ThreadPoolExecutor(max_workers=8) as pool:self.assertTrue(all(pool.map(parallel,range(64))))

    def test_actual_parser_entry_without_reference_grammar(self):
        from contextlib import ExitStack
        cases=[p.read_text() for p in (sorted((ROOT/'tests').rglob('*.hepta'))+sorted((ROOT/'examples').rglob('*.hepta')))[:300]]
        expected=[observed(s,lambda p:p._parse_reference()) for s in cases]
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ,{'HEPTA_HIA_SOURCE_PARSER_MANIFEST':str(self.manifest)}))
            for name in ('_parse_reference','_struct','_enum','_function','_type','_type_reference',
                         '_expr','_prefix','_statement','_block','_path','_field_name','_type_params',
                         '_function_type_params','_type_instantiation','_type_args','_validate_tree_depth',
                         '_abi','_effects','_resources','_type_close','_expressions'):
                stack.enter_context(patch.object(Parser,name,side_effect=AssertionError('foreign grammar called: '+name)))
            for i,source in enumerate(cases):
                with self.subTest(index=i):self.assertEqual(observed(source,lambda p:p.parse()),expected[i])
            from hepta.lexer import Lexer
            stack.enter_context(patch.dict(os.environ,{'HEPTA_HIA_SOURCE_LEXER_MANIFEST':str(self.lexer_manifest)}))
            stack.enter_context(patch.object(Lexer,'tokenize',side_effect=AssertionError('foreign lexer called')))
            for i,source in enumerate(cases):
                with self.subTest(native_lexer_index=i):self.assertEqual(observed(source,lambda p:p.parse()),expected[i])

    def test_explicit_profile_and_broken_artifact_refusal(self):
        bad=str(self.folder/'does-not-exist.json')
        with patch.dict(os.environ,{'HEPTA_HIA_SOURCE_PARSER_MANIFEST':bad}):
            with self.assertRaises((ValueError,FileNotFoundError)):Parser('fn f()->u8 effects {} {}').parse()
            with patch.object(Parser,'_parse_reference',return_value='outside') as reference:
                # Packet count is actual lexical token count, including EOF.
                p=Parser('a '*4096)
                self.assertEqual(p.parse(),'outside');reference.assert_called_once()
            with patch.object(Parser,'_parse_reference',return_value='outside') as reference:
                p=Parser('a'*(1<<20));self.assertEqual(p.parse(),'outside');reference.assert_called_once()
        for depth in (-1,97):
            p=Parser('');p.depth=depth
            with self.assertRaises(ValueError):packet(p)

    def test_exact_token_byte_profiles_and_nonzero_entry_cursor(self):
        # Build valid whole programs at each parity around the exact token cap.
        prefix='fn f()->u8 effects {} {'
        for target in (4095,4096):
            source=prefix+'1;'*((target-len(Parser(prefix+'}').tokens))//2)+'}'
            if len(Parser(source).tokens)<target:source=source.replace('1;','return 1;',1)
            self.assertEqual(len(Parser(source).tokens),target)
            self.compare(source)
        source='x'*((1<<20)-160)
        self.assertEqual(len(packet(Parser(source))),1<<20)
        self.compare(source)
        with self.assertRaises(ValueError):packet(Parser(source+'x'))
        for start in range(len(Parser('module m; fn f()->u8 effects {} {return 1;}').tokens)):
            text='module m; fn f()->u8 effects {} {return 1;}'
            def native(p):p.position=start;return self.native.parse(p)
            def reference(p):p.position=start;return p._parse_reference()
            self.assertEqual(observed(text,native),observed(text,reference))
