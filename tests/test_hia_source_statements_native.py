"""Actual HIA block/statement byte, grammar, cursor and refusal regressions."""
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import ctypes,json,os,random,struct,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from hepta.ast import HeptaError,Span,Stmt
from hepta.parser import Parser,parse,_MAX_NESTING
from hepta.hia_source_statements_native import SOURCE,SCHEMA,MAGIC,WORKSPACE,NativeSourceStatements,materialize,installed_source_statements,Block
from hepta.hia_source_lexer_native import NativeSourceLexer
ROOT=Path(__file__).resolve().parents[1]
NONE=(1<<64)-1


def vm_window(wire,begin=0,count=128,capacity=2048,block=True):
    from tools.hia_selfhost_bulk import Body
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import execute_program
    b=Body(0);owners=[];views=[]
    state=bytearray(WORKSPACE+((len(wire)+7)>>3));struct.pack_into('<Q',state,25040,128);struct.pack_into('<Q',state,25048,not block)
    for size,initial in ((len(wire),wire),(capacity,b''),(len(state),state)):
        owner=b.value('buffer','buffer.new',[b.const('usize',size)]);view=b.value('mutbuf','borrow.mut',[owner])
        for i,value in enumerate(initial):
            if value:b.effect('buffer.store',[view,b.const('usize',i),b.const('u8',value)])
        owners.append(owner);views.append(view)
    b.effect('loan.end',[views[0]]);views[0]=b.value('readbuf','borrow.read',[owners[0]])
    code=b.value('u32','call',views,{'function':'f0'})
    raw=[b.value('u8','buffer.load',[views[1],b.const('usize',i)]) for i in range(begin,begin+count)]
    for view in views:b.effect('loan.end',[view])
    for owner in owners:b.effect('owner.drop',[owner])
    source=('hia-asm.v1 hepta.hia.program.v8 source_statement_reference\nfn observe() -> (u32,'+','.join(['u8']*count)+') effects(alloc,read,write,trap) entry(b0)\nblock b0()\n'+b.text()+'  ret('+','.join([code,*raw])+')\nend\n'+SOURCE.read_text().split('\n',1)[1])
    result=execute_program(assemble_program(source),'observe',[],max_steps=2000000)
    assert result['status']=='returned',result
    code,*raw=result['values'];return code,bytes(raw)


def witnesses():
    result=[]
    for wire,block,rows in ((b'{}',True,[(32,NONE,NONE,NONE,NONE,0,0,0,0,0,0,2,1,1,0,0)]),
        (b'return;',False,[(34,NONE,NONE,NONE,NONE,0,0,0,0,0,0,7,1,1,0,0)]),
        (b'{return;}',True,[(32,NONE,1,1,NONE,0,0,0,0,0,0,9,1,1,0,0),(34,0,NONE,NONE,NONE,0,0,0,0,0,1,8,1,2,0,0)])):
        size=64+128*len(rows)
        expected=struct.pack('<8Q',MAGIC,len(rows),size,size,len(wire),len(wire),1,0)+b''.join(struct.pack('<16Q',*row) for row in rows)
        chunks=[]
        for begin in range(0,size,128):
            code,raw=vm_window(wire,begin,min(128,size-begin),block=block);assert code==size;chunks.append(raw)
        actual=b''.join(chunks);assert actual==expected,(wire,actual,expected)
        result.append((wire,block,actual))
    assert vm_window(b'{')[0]==0xffffffff
    return result


ENV=('HEPTA_HIA_SOURCE_STATEMENTS_MANIFEST','HEPTA_HIA_SOURCE_EXPRESSIONS_MANIFEST','HEPTA_HIA_SOURCE_TYPES_MANIFEST','HEPTA_HIA_SOURCE_LEXER_MANIFEST')
def outcome(source,manifest='',block=True,depth=0):
    with patch.dict('os.environ',{**{n:'' for n in ENV},ENV[0]:manifest}):
        parser=Parser(source,'statements.hepta');parser.depth=depth
        try:
            value=parser._block() if block else parser._statement()
            return 'ast',value,parser.tokens,parser.position,parser.depth,parser.qualified_expressions
        except HeptaError as error:return 'error',error.diagnostic.to_dict(),parser.tokens,parser.position,parser.depth,parser.qualified_expressions


class SourceStatementsSourceTests(unittest.TestCase):
    def test_generated_exact_and_independent_VM(self):
        from tools.generate_hia_source_statements import document
        from hepta.hia_agent_assembly import render_assembly
        self.assertEqual(SOURCE.read_text(),render_assembly(document()));self.assertEqual(len(witnesses()),3)


class SourceStatementsNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.witnesses=witnesses()
        from tools.qualify_hia_selfhost import build_seed,compile_stage
        cls.temp=tempfile.TemporaryDirectory(prefix='hia-source-statements-');cls.folder=Path(cls.temp.name)
        seed,_=build_seed(cls.folder);compiler=(ROOT/'examples/hia_bootstrap/selfhost.hiaasm').read_bytes()
        first,_=compile_stage(cls.folder,'B1',seed,compiler,image_format='seed-shared')
        second,_=compile_stage(cls.folder,'B2',first,compiler);assert first.read_bytes()==second.read_bytes()
        image,cls.receipt=compile_stage(cls.folder,'statements',second,SOURCE.read_bytes())
        cls.native=NativeSourceStatements(image.read_bytes(),sha256(image.read_bytes()).hexdigest())
        cls.manifest=cls.folder/'manifest.json';cls.manifest.write_text(json.dumps({'schema':SCHEMA,'source_sha256':sha256(SOURCE.read_bytes()).hexdigest(),'image_path':image.name,'image_sha256':sha256(image.read_bytes()).hexdigest(),'compiler_sha256':sha256(second.read_bytes()).hexdigest()}))
        lexer_source=ROOT/'examples/hia_bootstrap/source_lexer.hiaasm';lexer_image,_=compile_stage(cls.folder,'lexer',second,lexer_source.read_bytes())
        cls.lexer=NativeSourceLexer(lexer_image.read_bytes(),sha256(lexer_image.read_bytes()).hexdigest())
        directory=cls.folder/'source-lexer';directory.mkdir();(directory/'manifest.json').write_text(json.dumps({'schema':'hepta.hia.source-lexer-native.v2','source_sha256':sha256(lexer_source.read_bytes()).hexdigest(),'image_path':'../'+lexer_image.name,'image_sha256':sha256(lexer_image.read_bytes()).hexdigest(),'compiler_sha256':sha256(second.read_bytes()).hexdigest()}))

    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()

    def compare(self,source,block=True,depth=0):
        self.assertEqual(outcome(source,str(self.manifest),block,depth),outcome(source,block=block,depth=depth),repr(source[:220]))

    def test_native_bytes_match_independent_VM_before_seed(self):
        for wire,block,raw in self.witnesses:
            actual,_=self.native.run(wire,max_depth=128,block=block);self.assertEqual(actual,raw)
        self.assertEqual(self.receipt['forbidden_compiler_modules_loaded'],[])

    def test_complete_existing_statement_grammar_and_exact_cursors(self):
        statements=['let x=1;','let mut y: Buffer<[u8; 0xff]> = make::<u8>(7);','return;','return ns::f(7);',
            'for i in 0..10 { f(i); }','while x<10 {x=x+1;}','if x {return;} else {f();}',
            'unsafe {a.b[0]=2;}','match x {}','match x { R::Ok(v)=>{f(v);},R::Err(a,b)=>{return;} }',
            'match x { a::b::C(_)=>{} , }','[1,2][0]=3;','f(1+2, [3,4]);',
            'if a { if b {return;} else {} } else { unsafe {} }']
        for source in statements:
            for prefix in ('','/* π🙂 */\r\n  '):
                with self.subTest(source=source):self.compare(prefix+source,False);self.compare('{'+prefix+source+'}')
        self.compare('{'+' '.join(statements)+'} fn next()')

    def test_diagnostics_cursor_split_traces_qualified_observations_and_depth(self):
        invalid=['','{','{return','{let =0;}','{let x 1;}','{let x=;}','{let x=1}',
            '{return 1}','{for in 0..1 {}}','{for i on 0..1 {}}','{for i in 0 {}}',
            '{while x return;}','{if x {} else if y {}}','{unsafe return;}',
            '{match x {}}','{match x {Bad=>{}}}','{match x {R::=>{}}}',
            '{match x {R::C()=>{}}}','{match x {R::C(x,)=>{}}}','{match x {R::C(x) {}}}',
            '{match x {R::C=>{} R::D=>{}}}','{match x {R::C=>{return}}}',
            '{1=2;}','{(1+2)=3;}','{f()=1;}','{x=1}','{f()}','{let x:X<X<T>>=v;}','{ns::f(); return 1+;}']
        for source in invalid:
            for prefix in ('','/* π🙂 */\r\n  '):
                with self.subTest(source=source):self.compare(prefix+source)
        for depth in (0,1,40,94,95,96):
            for source in ('{}','{return;}','{return 1;}','{unsafe {}}','{let x:[u8]=[1];}'):
                self.compare(source,True,depth)
            for source in ('return;','return 1;','unsafe {}','let x:[u8]=[1];'):
                self.compare(source,False,depth)
        for depth in (94,95,96,97):self.compare('unsafe {'*depth+'return;'+'}'*depth,False)

    def test_mixed_deterministic_nested_blocks(self):
        rng=random.Random(0x57a7e2026)
        def make(depth):
            if depth==0:return rng.choice(['return;','let x=ns::f(1);','x[0]=2;','f();','match x {R::C(v)=>{return v;},}'])
            body=make(depth-1)
            return rng.choice(['if x {'+body+'} else {return;}','while x {'+body+'}','unsafe {'+body+'}', 'for i in 0..4 {'+body+'}'])
        for _ in range(160):
            source=make(rng.randrange(0,9));self.compare('{'+source+'}')
            self.compare('{'+source[:rng.randrange(len(source)+1)]+'}')

    def test_real_repository_AST_and_real_callers_cannot_use_foreign_grammar(self):
        paths=sorted((ROOT/'tests').rglob('*.hepta'))+sorted((ROOT/'examples').rglob('*.hepta'))
        for path in paths[:300]:
            def call(manifest):
                with patch.dict('os.environ',{**{n:'' for n in ENV},ENV[0]:manifest}):
                    try:return 'ast',parse(path.read_text(),str(path))
                    except HeptaError as error:return 'error',error.diagnostic.to_dict()
            self.assertEqual(call(str(self.manifest)),call(''),str(path))
        source='module demo; enum R { C(u8) } fn f(x:u8)->u8 effects{} {let y:[u8;1]=[x]; match R::C(x) {R::C(v)=>{if v>0 {return y[0];} else {return 0;}},} return x;}'
        with patch.dict('os.environ',{n:'' for n in ENV}):expected=parse(source)
        with patch.dict('os.environ',{**{n:'' for n in ENV},ENV[0]:str(self.manifest)}), \
            patch.object(Parser,'_reference_block',side_effect=AssertionError('foreign block')) ,\
            patch.object(Parser,'_reference_statement',side_effect=AssertionError('foreign statement')),\
            patch.object(Parser,'_reference_expr',side_effect=AssertionError('foreign expression')),\
            patch('hepta.lexer.Lexer.tokenize',side_effect=AssertionError('foreign lexer')):
            with ThreadPoolExecutor(max_workers=8) as pool:self.assertEqual(list(pool.map(parse,[source]*32)),[expected]*32)

    def test_transactional_refusal_and_poisoned_workspace(self):
        for wire,capacity,size,depth,entry,wanted in ((b'{}',1,WORKSPACE+1,128,0,0xfffffffe),
            (b'{}',512,WORKSPACE,128,0,0xfffffffd),(b'{}',512,WORKSPACE+1,129,0,0xfffffffd),
            (b'{}',512,WORKSPACE+1,128,2,0xfffffffd),(b'{',512,WORKSPACE+1,128,0,0xffffffff),
            (b'{1=2;}',2048,WORKSPACE+1,128,0,0xffffffff)):
            source=ctypes.create_string_buffer(wire,len(wire));output=ctypes.create_string_buffer(b'\xa5'*(capacity+8),capacity+8)
            state=ctypes.create_string_buffer(b'\x00'*size+b'\x5a'*8,size+8)
            struct.pack_into('<Q',state,25040,depth);struct.pack_into('<Q',state,25048,entry)
            self.assertEqual(self.native._entry(source,len(wire),output,capacity,state,size),wanted)
            self.assertEqual(output.raw,b'\xa5'*(capacity+8));self.assertEqual(state.raw[size:],b'\x5a'*8)

    def test_graph_rejects_cross_kind_roots_aliases_cycles_unowned_payload_and_modes(self):
        wire=b'{let x=7;return x;}';raw,_=self.native.run(wire,max_depth=128)
        def literal(begin,size,kind):self.assertEqual(kind,'INT');return 7
        tree,*_=materialize(raw,wire,self.lexer.integer_value,literal);self.assertIsInstance(tree,Block)
        for offset,value in ((0,0),(8,0),(16,0),(24,len(raw)+1),(48,2),(56,1),(64,16),(72,0),(80,0),(88,99),(104,1),(136,1),(64+128+72,2)):
            bad=bytearray(raw);struct.pack_into('<Q',bad,offset,value)
            with self.subTest(offset=offset),self.assertRaises(ValueError):materialize(bytes(bad),wire,self.lexer.integer_value,literal)
        diagnostic,_=self.native.run(b'{ns::f();return 1+;}',max_depth=128,diagnostic_trace=True)
        with self.assertRaises(ValueError):materialize(diagnostic,b'{ns::f();return 1+;}',self.lexer.integer_value,literal)
        self.assertIsNotNone(installed_source_statements(str(self.manifest)))

    def test_native_statement_type_expression_recognizers_cannot_fall_back(self):
        source="{let x: Buffer<[u8;0xff]> = ns::make::<u8>(7); for i in 0..4 {x[i]=1;} return ns::f(x);}"
        with patch.dict('os.environ',{n:'' for n in ENV}):expected=Parser(source,'statements.hepta')._block()
        with patch.dict('os.environ',{**{n:'' for n in ENV},ENV[0]:str(self.manifest)}), \
            patch.object(Parser,'_reference_type',side_effect=AssertionError('foreign type')), \
            patch.object(Parser,'_reference_expr',side_effect=AssertionError('foreign expression')), \
            patch.object(Parser,'_reference_statement',side_effect=AssertionError('foreign statement')), \
            patch.object(Parser,'_reference_block',side_effect=AssertionError('foreign block')), \
            patch('hepta.lexer.Lexer.tokenize',side_effect=AssertionError('foreign lexer')):
            self.assertEqual(Parser(source,'statements.hepta')._block(),expected)

