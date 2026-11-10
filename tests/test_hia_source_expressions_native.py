"""Actual HIA expression grammar: independent VM before native successors."""
from __future__ import annotations
import ctypes
from hashlib import sha256
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
from hepta.ast import Expr, HeptaError, Span, Type
from hepta.hia_source_expressions_native import SOURCE, SCHEMA, WORKSPACE, NativeSourceExpressions, materialize
from hepta.hia_source_lexer_native import NativeSourceLexer
from hepta.parser import Parser
ROOT = Path(__file__).resolve().parents[1]


def vm_window(wire, begin=0, count=128, capacity=2048, depth=128):
    from tools.hia_selfhost_bulk import Body
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import execute_program
    b=Body(0); owners=[]; views=[]
    state=bytearray(WORKSPACE+((len(wire)+7)>>3));struct.pack_into('<Q',state,8520,depth);struct.pack_into('<Q',state,8552,1)
    for size,initial in ((len(wire),wire),(capacity,b''),(len(state),state)):
        owner=b.value('buffer','buffer.new',[b.const('usize',size)])
        view=b.value('mutbuf','borrow.mut',[owner])
        for i,value in enumerate(initial):
            if value:b.effect('buffer.store',[view,b.const('usize',i),b.const('u8',value)])
        owners.append(owner);views.append(view)
    b.effect('loan.end',[views[0]]);views[0]=b.value('readbuf','borrow.read',[owners[0]])
    code=b.value('u32','call',views,{'function':'f0'})
    raw=[b.value('u8','buffer.load',[views[1],b.const('usize',i)]) for i in range(begin,begin+count)]
    for view in views:b.effect('loan.end',[view])
    for owner in owners:b.effect('owner.drop',[owner])
    source=('hia-asm.v1 hepta.hia.program.v8 source_expression_reference\nfn observe() -> (u32,'+','.join(['u8']*count)+') effects(alloc,read,write,trap) entry(b0)\nblock b0()\n'+b.text()+'  ret('+','.join([code,*raw])+')\nend\n'+SOURCE.read_text().split('\n',1)[1])
    result=execute_program(assemble_program(source),'observe',[],max_steps=2000000)
    assert result['status']=='returned',result
    code,*raw=result['values'];return code,bytes(raw)


def witnesses():
    result=[]
    for wire in (b'7',b'foo',b'1+2',b'f::<u8>(7)'):
        code,first=vm_window(wire);assert 64<=code<=2048
        data=[first]
        for begin in range(128,code,128):
            again,chunk=vm_window(wire,begin,min(128,code-begin));assert again==code;data.append(chunk)
        raw=b''.join(data)[:code]
        known={b'7':7,b'1':1,b'2':2}
        def literal(begin,length,kind):
            assert kind=='INT'
            return known[wire[begin:begin+length]]
        value,chars,consumed,names,splits=materialize(raw,wire,
            lambda _:(_ for _ in ()).throw(AssertionError('unexpected integer type')),literal)
        expected={b'7':Expr('int',7,span=Span(0,1)),b'foo':Expr('name','foo',span=Span(0,3)),
            b'1+2':Expr('binary','+',[Expr('int',1,span=Span(0,1)),Expr('int',2,span=Span(2,3,1,3))],Span(0,3)),
            b'f::<u8>(7)':Expr('call','f',[Expr('int',7,span=Span(8,9,1,9))],Span(0,10),(Type('u8'),))}[wire]
        assert value==expected and chars==consumed==len(wire) and names==[] and splits==set(), (wire,value,expected,chars,consumed,names,splits)
        result.append((wire,raw))
    assert vm_window(b'(')[0]==0xffffffff
    return result


def outcome(source,selected=None,minimum=0,allow=True,depth=0):
    with patch.dict('os.environ',{'HEPTA_HIA_SOURCE_EXPRESSIONS_MANIFEST':selected or '',
        'HEPTA_HIA_SOURCE_TYPES_MANIFEST':'','HEPTA_HIA_SOURCE_LEXER_MANIFEST':''}):
        parser=Parser(source,'expressions.hepta');parser.depth=depth
        try:
            expr=parser._expr(minimum,allow)
            return 'expr',expr,parser.tokens,parser.position,parser.depth,parser.qualified_expressions
        except HeptaError as error:return 'error',error.diagnostic.to_dict(),parser.tokens,parser.position,parser.depth,parser.qualified_expressions


class SourceExpressionsSourceTests(unittest.TestCase):
    def test_generated_exact_and_independent_VM(self):
        from tools.generate_hia_source_expressions import document
        from hepta.hia_agent_assembly import render_assembly
        self.assertEqual(SOURCE.read_text(),render_assembly(document()))
        self.assertEqual(len(witnesses()),4)


class SourceExpressionsNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.witnesses=witnesses()
        from tools.qualify_hia_selfhost import build_seed,compile_stage
        cls.temporary=tempfile.TemporaryDirectory(prefix='hia-source-expressions-');cls.folder=Path(cls.temporary.name)
        seed,_=build_seed(cls.folder)
        compiler=(ROOT/'examples/hia_bootstrap/selfhost.hiaasm').read_bytes()
        first,_=compile_stage(cls.folder,'B1',seed,compiler,image_format='seed-shared')
        second,_=compile_stage(cls.folder,'B2',first,compiler);assert first.read_bytes()==second.read_bytes()
        image,cls.receipt=compile_stage(cls.folder,'expressions',second,SOURCE.read_bytes())
        cls.native=NativeSourceExpressions(image.read_bytes(),sha256(image.read_bytes()).hexdigest())
        cls.manifest=cls.folder/'manifest.json';cls.manifest.write_text(json.dumps({'schema':SCHEMA,'source_sha256':sha256(SOURCE.read_bytes()).hexdigest(),'image_path':image.name,'image_sha256':sha256(image.read_bytes()).hexdigest(),'compiler_sha256':sha256(second.read_bytes()).hexdigest()}))
        lexer_source=ROOT/'examples/hia_bootstrap/source_lexer.hiaasm'
        lexer_image,_=compile_stage(cls.folder,'lexer',second,lexer_source.read_bytes())
        cls.lexer=NativeSourceLexer(lexer_image.read_bytes(),sha256(lexer_image.read_bytes()).hexdigest())
        directory=cls.folder/'source-lexer';directory.mkdir();(directory/'manifest.json').write_text(json.dumps({'schema':'hepta.hia.source-lexer-native.v2','source_sha256':sha256(lexer_source.read_bytes()).hexdigest(),'image_path':'../'+lexer_image.name,'image_sha256':sha256(lexer_image.read_bytes()).hexdigest(),'compiler_sha256':sha256(second.read_bytes()).hexdigest()}))

    @classmethod
    def tearDownClass(cls):cls.temporary.cleanup()

    def compare(self,source,minimum=0,allow=True,depth=0):
        self.assertEqual(outcome(source,str(self.manifest),minimum,allow,depth),outcome(source,None,minimum,allow,depth),repr(source[:200]))

    def test_native_bytes_match_independent_VM_before_seed(self):
        for wire,raw in self.witnesses:
            actual,_=self.native.run(wire,max_depth=128);self.assertEqual(actual,raw)
        self.assertEqual(self.receipt['forbidden_compiler_modules_loaded'],[])

    def test_complete_grammar(self):
        for source in ('7','0x77','1.25','true','false','foo','foo::bar',
            '-1+2*3','read x','mut x','move x','!false','(-x).match',
            'a||b&&c|d^e&f==g<h<<i+j*k', 'a-b-c','a/b/c','1<<2>>3',
            'x as raw const u8','x as Buffer<[u8;0x77]>','x as X<X<T>>==0',
            'foo()','foo(1,2,)','foo(1)[2].value','a[1+2][4]','[1,2,]','[]',
            '(foo)(3)','((1+2))*3','foo::<u8>(7)','X::<u8>::value',
            'X::<X<X<T>>>::field(7)','X::<X<T>>=0',
            'S{}','S{match:1,value:foo(2),}','S::<u8>{x:7}',
            'a /* π🙂 */ +\r\n (b * 2)','(/*π*/pkg::call::<u8>)(2)',
            'foo::<[u8;0x7f]>()', '[[1],[2]]'):
            with self.subTest(source=source):self.compare(source)
        for source in ('x { y:1 }','x+S{y:2}','-S{y:2}','(S{y:2})','f(S{y:2})'):
            self.compare(source,allow=False)
        for minimum in range(13):self.compare('a + b * c as u64 == d',minimum)

    def test_diagnostics_and_exact_cursor(self):
        for source in ('','(',')','[',']','{','foo(', 'foo(,)', 'foo(1 2)',
            'a[', 'a[1', 'a.','a.fn','a.1','1(2)','f()()',
            'S{x}','S{x:}','S{x:1 y:2}','S{x:1,fn:2}','S{',
            'a::','a::fn','a::<>','a::<u8,>','a::<u8>::<u64>',
            'x as', 'x as raw u8', 'x as X<>', '"C"', '-','a+','a+)',
            'X::<X<T>>+', 'X::<X<T>>::<u8>', 'S::<u8>{x:}', 'a["C"]'):
            for prefix in ('','/* π🙂 */\r\n  '):
                with self.subTest(source=prefix+source):self.compare(prefix+source)
        for depth in (0,40,94,95,96):
            for source in ('1','-1','((1))','x as [[u8]]','f(g(1))'):
                self.compare(source,depth=depth)

    def test_fuzzed_composition_and_every_binary_precedence(self):
        import random
        randomizer=random.Random(917414)
        def expression(depth):
            if not depth:return randomizer.choice(['1','2.5','true','x','a::b','x::<u8>'])
            mode=randomizer.randrange(9)
            if mode==0:return '('+expression(depth-1)+')'
            if mode==1:return '-'+expression(depth-1)
            if mode==2:return '['+expression(depth-1)+','+expression(depth-1)+',]'
            if mode==3:return 'S{x:'+expression(depth-1)+'}'
            if mode==4:return expression(depth-1)+' as X<X<u8>>'
            if mode==5:return 'f('+expression(depth-1)+')'
            if mode==6:return expression(depth-1)+'[1]'
            if mode==7:return expression(depth-1)+'.match'
            return expression(depth-1)+randomizer.choice(['+','-','*','==','>>','&&'])+expression(depth-1)
        for _ in range(300):self.compare(expression(3))
        from hepta.parser import _BINARY
        for a in _BINARY:
            for b in _BINARY:self.compare('x '+a+' y '+b+' z')

    def test_native_frame_boundary_and_long_left_chain(self):
        self.compare('+'.join(['1']*140))
        for wrappers in (94,95,96,97):self.compare('('*wrappers+'1'+')'*wrappers)
        for wrappers,valid in ((127,True),(128,False)):
            raw,state=self.native.run(('('*wrappers+'1'+')'*wrappers).encode(),max_depth=128)
            self.assertEqual(raw is not None,valid)

    def test_actual_parser_no_foreign_expression_or_type_grammar(self):
        from concurrent.futures import ThreadPoolExecutor
        sources=['f::<X<X<u8>>>(S{x:1+2}).match[0]','(a::b::<[u8;0x7f]>)(-2) as raw const u8','[1,2*3,4>>1]']
        expected=[outcome(source)[1] for source in sources]
        with patch.dict('os.environ',{'HEPTA_HIA_SOURCE_EXPRESSIONS_MANIFEST':str(self.manifest),'HEPTA_HIA_SOURCE_TYPES_MANIFEST':''}):
            with patch.object(Parser,'_reference_expr',side_effect=AssertionError('foreign expression')),patch.object(Parser,'_prefix',side_effect=AssertionError('foreign prefix')),patch.object(Parser,'_expressions',side_effect=AssertionError('foreign argument grammar')),patch.object(Parser,'_type_args',side_effect=AssertionError('foreign generics')),patch.object(Parser,'_reference_type',side_effect=AssertionError('foreign type')),patch('hepta.lexer.Lexer.tokenize',side_effect=AssertionError('foreign lexer')):
                with ThreadPoolExecutor(max_workers=4) as pool:
                    actual=list(pool.map(lambda source:Parser(source,'expressions.hepta')._expr(),sources*4))
        self.assertEqual(actual,expected*4)

    def test_transactional_refusals_and_poisoned_guards(self):
        for wire,capacity,depth,wanted in ((b'(',2048,128,0xffffffff),(b'1+2',16,128,0xfffffffe),(b'1',2048,0,0xfffffffd)):
            with self.subTest(wire=wire,capacity=capacity,depth=depth):
                source=ctypes.create_string_buffer(wire);output=ctypes.create_string_buffer(b'Q'*(capacity+16),capacity+16)
                workspace=WORKSPACE+((len(wire)+7)>>3);state=ctypes.create_string_buffer(workspace)
                struct.pack_into('<Q',state,8520,depth);struct.pack_into('<Q',state,8552,1)
                self.assertEqual(self.native._entry(source,len(wire),output,capacity,state,workspace),wanted)
                self.assertEqual(output.raw,b'Q'*(capacity+16))
        wire=b'foo::<X<X<T>>>(1 as u8)+2>>1';source=ctypes.create_string_buffer(wire);capacity=8192
        output=ctypes.create_string_buffer(b'Q'*(capacity+16),capacity+16);workspace=WORKSPACE+((len(wire)+7)>>3);state=ctypes.create_string_buffer(workspace)
        struct.pack_into('<Q',state,8520,128);struct.pack_into('<Q',state,8552,1)
        size=self.native._entry(source,len(wire),output,capacity,state,workspace)
        self.assertGreater(size,64);self.assertEqual(output.raw[size:],b'Q'*(capacity+16-size))

    def test_namespaces_cursor_on_invalid_qualified_calls(self):
        for source in ('a::b(','a::b(]','a::b+','f(a::b,]','S{x:a::b, y:}','a::b::<u8>::<u8>'):
            with self.subTest(source=source):self.compare(source)

    def test_existing_split_initial_operator_tokens_are_not_recombined(self):
        for source in ('X<T>>>','X<T>>=1','X<T>==1'):
            results=[]
            for selected in ('',str(self.manifest)):
                with patch.dict('os.environ',{'HEPTA_HIA_SOURCE_EXPRESSIONS_MANIFEST':selected,'HEPTA_HIA_SOURCE_TYPES_MANIFEST':''}):
                    parser=Parser(source,'split.hepta');parser._type()
                    try:parser._expr();self.fail('invalid operator must not become an expression')
                    except HeptaError as error:results.append((error.diagnostic.to_dict(),parser.tokens,parser.position))
            self.assertEqual(*results)

    def test_malformed_arena_graph_ranges_and_diagnostic_separation(self):
        wire=b'f::<X<u8>>(S{x:7}).value + 2 >> 1'
        raw,state=self.native.run(wire,max_depth=128)
        tokens=self.lexer.tokenize(wire.decode());values={}
        for token in tokens:
            begin=token.span.start;values[(begin,token.span.end-begin,token.kind)]=token.value
        callback=lambda begin,length,kind:values[(begin,length,kind)]
        materialize(raw,wire,self.lexer.integer_value,callback)
        for offset,value in ((0,0),(8,1<<20|1),(16,0),(24,len(raw)-1),(32,0),(56,1<<63),(64+8,0),(64+16,0),(64+24,0)):
            bad=bytearray(raw);struct.pack_into('<Q',bad,offset,value)
            with self.subTest(offset=offset):
                with self.assertRaises(ValueError):materialize(bytes(bad),wire,self.lexer.integer_value,callback)
        diagnostic,_=self.native.run(b'pkg::value(',max_depth=128,diagnostic_trace=True)
        with self.assertRaises(ValueError):materialize(diagnostic,b'pkg::value(',self.lexer.integer_value,callback)
        from hepta.hia_source_expressions_native import materialize_diagnostic_names
        self.assertEqual(materialize_diagnostic_names(diagnostic,b'pkg::value(')[0][0],'pkg::value')
        with self.assertRaises(ValueError):materialize_diagnostic_names(raw,wire)

    def test_real_complete_source_corpus_with_reference_expression_disabled(self):
        from hepta.parser import parse
        samples=sorted((ROOT/'examples').rglob('*.hepta'))[:100]
        self.assertGreater(len(samples),20)
        for path in samples:
            source=path.read_text()
            with patch.dict('os.environ',{'HEPTA_HIA_SOURCE_EXPRESSIONS_MANIFEST':'','HEPTA_HIA_SOURCE_TYPES_MANIFEST':''}):
                try:expected=('program',parse(source,str(path)))
                except HeptaError as error:expected=('error',error.diagnostic.to_dict())
            with patch.dict('os.environ',{'HEPTA_HIA_SOURCE_EXPRESSIONS_MANIFEST':str(self.manifest),'HEPTA_HIA_SOURCE_TYPES_MANIFEST':''}):
                with patch.object(Parser,'_reference_expr',side_effect=AssertionError('foreign expression')),patch.object(Parser,'_prefix',side_effect=AssertionError('foreign prefix')),patch.object(Parser,'_expressions',side_effect=AssertionError('foreign list')):
                    try:actual=('program',parse(source,str(path)))
                    except HeptaError as error:actual=('error',error.diagnostic.to_dict())
            self.assertEqual(actual,expected,str(path))
