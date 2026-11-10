"""Native full source syntax: independent bytes, AST/state, failures and callers."""
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import ctypes,json,os,random,struct,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from hepta.ast import HeptaError,Program
from hepta.parser import Parser
from hepta.hia_source_declarations_native import SOURCE,SCHEMA,MAGIC,WORKSPACE,NativeSourceDeclarations,materialize,installed_source_declarations
from hepta.hia_source_lexer_native import NativeSourceLexer
ROOT=Path(__file__).resolve().parents[1]
NONE=(1<<64)-1
ENV=('HEPTA_HIA_SOURCE_DECLARATIONS_MANIFEST','HEPTA_HIA_SOURCE_STATEMENTS_MANIFEST','HEPTA_HIA_SOURCE_EXPRESSIONS_MANIFEST','HEPTA_HIA_SOURCE_TYPES_MANIFEST','HEPTA_HIA_SOURCE_LEXER_MANIFEST')


def vm_window(wire,begin,count,capacity=1024):
    from tools.hia_selfhost_bulk import Body
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import execute_program
    b=Body(0);owners=[];views=[]
    state=bytearray(WORKSPACE+((len(wire)+7)>>3));struct.pack_into('<Q',state,25040,96)
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
    source=('hia-asm.v1 hepta.hia.program.v8 source_declaration_reference\nfn observe() -> (u32,'+','.join(['u8']*count)+') effects(alloc,read,write,trap) entry(b0)\nblock b0()\n'+b.text()+'  ret('+','.join([code,*raw])+')\nend\n'+SOURCE.read_text().split('\n',1)[1])
    result=execute_program(assemble_program(source),'observe',[],max_steps=2000000)
    assert result['status']=='returned',result
    code,*raw=result['values'];return code,bytes(raw)


def witnesses():
    result=[]
    for wire,kind,a,z,name in ((b'',None,0,0,b''),(b'module a;',49,7,8,b'a'),(b'struct S {}',52,0,11,b'S')):
        root=(48,NONE,1 if kind else NONE,1 if kind else NONE,NONE,0,0,0,0,0,0,len(wire),1,1,0,0)
        rows=[root]
        if kind:rows.append((kind,0,NONE,NONE,NONE,0,len(name),0,0,0,a,z,1,a+1,0,0))
        base=64+128*len(rows);size=base+len(name)
        expected=struct.pack('<8Q',MAGIC,len(rows),base,size,len(wire),len(wire),1,0)+b''.join(struct.pack('<16Q',*r) for r in rows)+name
        chunks=[]
        for begin in range(0,size,128):
            code,raw=vm_window(wire,begin,min(128,size-begin));assert code==size;chunks.append(raw)
        actual=b''.join(chunks);assert actual==expected,(wire,actual,expected)
        result.append((wire,actual))
    assert vm_window(b'module;',0,1)[0]==0xffffffff
    return result


def outcome(source,manifest=''):
    with patch.dict('os.environ',{**{n:'' for n in ENV},ENV[0]:manifest}):
        try:parser=Parser(source,'declarations.hepta')
        except HeptaError as error:return 'lex',error.diagnostic.to_dict()
        try:result='ast',parser.parse()
        except HeptaError as error:result='error',error.diagnostic.to_dict()
        return (*result,parser.tokens,parser.position,parser.depth,parser.qualified_expressions)


SAMPLES=['','/* π🙂 */','module demo;','module a::b; import x::y; import z as q;',
 'struct S {}','pub repr(C) struct S {x:u8,match:u64,}',"struct S<'a,T> {x:read 'a T,}",
 'struct S<T:Owned,T> {}','struct S<T,T:Owned> {}','struct S<T:Owned,U:Copy,T:Copy> {}',
 'struct S<T:Bad,U> {}','enum E<T> {A,B(T),C(u8,u64),}','pub enum E {}',
 'fn f()->u8 effects{} {return 7;}',
 "pub fn f<'a,T:Owned>(x:read 'a T,y:take T,)->read 'a T from x effects{alloc,unsafe} {return x;}",
 'extern "C" fn f(x:u8)->u64 effects{unsafe};',
 'pub export "C" fn f()->u32 effects{} resources{steps=1;stack=false;ratio=1.5;} {return 0;}',
 'fn f()->u8 effects{a,a} {}','fn f()->u8 effects{unsafe,unsafe} {}',
 'fn f()->u8 effects{} resources{x=1;x=2;} {}','fn f()->u8 effects{} resources{x=-1;} {}',
 'fn f()->u8 effects{} {let x:Buffer<Buffer<u8>>=make::<u8>(7);if x[0]>0 {return 1;}else{return 2;}}',
 'module;','struct S<T: Owned> {}','extern "D" fn f()->u8 effects{};',
 'enum E {A(),}','fn f()->u8 effects{}','repr(D) struct S {}','pub extern "C" fn f()->u8 effects{};',
 'fn f<T:Bad>()->u8 effects{} {}',"fn f<'a,>()->u8 effects{} {}",'import a::b as c;',
 'fn f()->u8 effects{} {return Missing::f();}','fn f()->u8 effects{} {return Result::Ok(1);}']


class SourceDeclarationsSourceTests(unittest.TestCase):
    def test_generated_exact_and_independent_VM(self):
        from tools.generate_hia_source_declarations import document
        from hepta.hia_agent_assembly import render_assembly
        self.assertEqual(SOURCE.read_text(),render_assembly(document()));self.assertEqual(len(witnesses()),3)


class SourceDeclarationsNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # All full-byte independent interpreter controls run BEFORE B0/native.
        cls.witnesses=witnesses()
        from tools.qualify_hia_selfhost import build_seed,compile_stage
        cls.temp=tempfile.TemporaryDirectory(prefix='hia-source-declarations-');cls.folder=Path(cls.temp.name)
        seed,_=build_seed(cls.folder);compiler=(ROOT/'examples/hia_bootstrap/selfhost.hiaasm').read_bytes()
        first,_=compile_stage(cls.folder,'B1',seed,compiler,image_format='seed-shared')
        second,_=compile_stage(cls.folder,'B2',first,compiler);assert first.read_bytes()==second.read_bytes()
        image,cls.receipt=compile_stage(cls.folder,'declarations',second,SOURCE.read_bytes())
        cls.native=NativeSourceDeclarations(image.read_bytes(),sha256(image.read_bytes()).hexdigest())
        cls.manifest=cls.folder/'manifest.json';cls.manifest.write_text(json.dumps({'schema':SCHEMA,'source_sha256':sha256(SOURCE.read_bytes()).hexdigest(),'image_path':image.name,'image_sha256':sha256(image.read_bytes()).hexdigest(),'compiler_sha256':sha256(second.read_bytes()).hexdigest()}))
        lexer_source=ROOT/'examples/hia_bootstrap/source_lexer.hiaasm';lexer_image,_=compile_stage(cls.folder,'lexer',second,lexer_source.read_bytes())
        cls.lexer=NativeSourceLexer(lexer_image.read_bytes(),sha256(lexer_image.read_bytes()).hexdigest())
        directory=cls.folder/'source-lexer';directory.mkdir();(directory/'manifest.json').write_text(json.dumps({'schema':'hepta.hia.source-lexer-native.v2','source_sha256':sha256(lexer_source.read_bytes()).hexdigest(),'image_path':'../'+lexer_image.name,'image_sha256':sha256(lexer_image.read_bytes()).hexdigest(),'compiler_sha256':sha256(second.read_bytes()).hexdigest()}))

    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()

    def compare(self,source):self.assertEqual(outcome(source,str(self.manifest)),outcome(source),repr(source[:220]))

    def test_native_bytes_match_independent_VM_before_seed(self):
        for wire,raw in self.witnesses:self.assertEqual(self.native.run(wire,max_depth=96)[0],raw)
        self.assertEqual(self.receipt['forbidden_compiler_modules_loaded'],[])

    def test_complete_declarations_spans_and_diagnostics(self):
        for source in SAMPLES:
            for prefix in ('','/* π🙂 */\r\n  '):
                with self.subTest(source=source):self.compare(prefix+source+' /* end */')
        for n in (94,95,96,97):
            self.compare('fn f()->u8 effects{} {'+'unsafe {'*n+'return 1;'+'}'*n+'}')
            self.compare('struct S { x:'+'Buffer<'*n+'u8'+'>'*n+' }')
        self.compare('fn f()->u8 effects{} {return '+'+'.join(['1']*200)+';}')

    def test_every_declaration_prefix_keeps_first_error_cursor(self):
        for source in SAMPLES:
            for i in range(len(source)+1):self.compare(source[:i])
        for source in ('pub r','pub repr(C) struc','extern "C" f','pub export "C" f','struct S<T:Owned,T> {','fn f(x u8)->u8 effects{} {}'):
            self.compare(source)

    def test_seeded_mutations_and_original_repository_AST(self):
        rng=random.Random(0xdeca2026)
        for _ in range(200):
            source=rng.choice(SAMPLES);at=rng.randrange(len(source)+1)
            self.compare(source[:at]+rng.choice(['pub','}',',',':','from','unsafe',';','<','>'])+source[at:])
        for path in sorted((ROOT/'tests').rglob('*.hepta'))+sorted((ROOT/'examples').rglob('*.hepta')):
            self.compare(path.read_text())

    def test_actual_callers_cannot_use_any_foreign_syntax_recognizer(self):
        source="module demo; import ext as e; pub repr(C) struct S<'a,T> {x:read 'a T,match:u8} enum E<T>{A,B(T)} extern \"C\" fn ext(x:u8)->u8 effects{unsafe}; pub fn f<'a,T:Owned>(x:read 'a T,y:u8)->u8 effects{} resources{steps=1;} {let z:[u8;1]=[y]; match E::B(y) {E::B(v)=>{if v>0 {return z[0];} else {return 0;}},} return y;}"
        expected=outcome(source)[1];self.assertIsInstance(expected,Program)
        from contextlib import ExitStack
        with patch.dict('os.environ',{**{n:'' for n in ENV},ENV[0]:str(self.manifest)}),ExitStack() as stack:
            for name in ('_path','_struct','_enum','_function','_abi','_effects','_resources','_type_params','_function_type_params','_reference_type','_reference_expr','_reference_statement','_reference_block'):
                stack.enter_context(patch.object(Parser,name,side_effect=AssertionError('foreign syntax '+name)))
            stack.enter_context(patch('hepta.lexer.Lexer.tokenize',side_effect=AssertionError('foreign lexer')))
            with ThreadPoolExecutor(max_workers=8) as pool:self.assertEqual(list(pool.map(lambda _:Parser(source,'declarations.hepta').parse(),range(32))),[expected]*32)

    def test_transactional_refusals_and_workspace_guards(self):
        for wire,capacity,size,depth,wanted in ((b'',1,WORKSPACE,96,0xfffffffe),
            (b'module a;',1024,WORKSPACE,96,0xfffffffd),(b'',1024,WORKSPACE,0,0xfffffffd),
            (b'',1024,WORKSPACE,129,0xfffffffd),(b'module;',1024,WORKSPACE+1,96,0xffffffff),
            (b'fn f()->u8 effects{a,a}{}',4096,WORKSPACE+4,96,0xffffffff)):
            source=ctypes.create_string_buffer(wire,max(1,len(wire)));output=ctypes.create_string_buffer(b'\xa5'*(capacity+8),capacity+8)
            state=ctypes.create_string_buffer(b'\x00'*size+b'\x5a'*8,size+8);struct.pack_into('<Q',state,25040,depth)
            self.assertEqual(self.native._entry(source,len(wire),output,capacity,state,size),wanted)
            self.assertEqual(output.raw,b'\xa5'*(capacity+8));self.assertEqual(state.raw[size:],b'\x5a'*8)

    def test_graph_refuses_wrong_ownership_tags_order_and_empty_old_profiles(self):
        wire=b'struct S {}';raw,_=self.native.run(wire,max_depth=96)
        literal=lambda *args:(_ for _ in ()).throw(AssertionError('no literal'))
        materialize(raw,wire,self.lexer.integer_value,literal)
        for offset,value in ((0,0),(8,0),(16,0),(24,len(raw)+1),(48,2),(56,1),(64,16),(72,0),(80,0),(88,99),(104,1),(136,1),(64+128+72,4),(64+128,64)):
            bad=bytearray(raw);struct.pack_into('<Q',bad,offset,value)
            with self.subTest(offset=offset),self.assertRaises(ValueError):materialize(bytes(bad),wire,self.lexer.integer_value,literal)
        from hepta.hia_source_expressions_native import materialize as old_expr
        from hepta.hia_source_statements_native import materialize as old_stmt
        empty=self.witnesses[0][1]
        for decoder in (old_expr,old_stmt):
            with self.assertRaises(ValueError):decoder(empty,b'',self.lexer.integer_value,literal)
        self.assertIsNotNone(installed_source_declarations(str(self.manifest)))
