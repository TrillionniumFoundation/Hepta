"""Actual HIA/VM module-symbol policy and no-host-resolver project integration."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
import ctypes
from hashlib import sha256
import json,os
from pathlib import Path
import random,struct,tempfile,unittest
from types import SimpleNamespace as NS
from unittest.mock import patch
from hepta.ast import Span,HeptaError
from hepta.hia_module_symbols_native import SOURCE,SCHEMA,NativeModuleSymbols,packet,installed_module_symbols
from hepta.modules import _resolve_reference,load_project
ROOT=Path(__file__).resolve().parents[1]


def vm(wire):
    from tools.hia_selfhost_bulk import Body
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import execute_program
    b=Body(0);owners=[];views=[]
    for size,initial in ((len(wire),wire),(128,b''),(1,b'')):
        owner=b.value('buffer','buffer.new',[b.const('usize',size)])
        view=b.value('mutbuf','borrow.mut',[owner])
        for i,value in enumerate(initial):
            if value:b.effect('buffer.store',[view,b.const('usize',i),b.const('u8',value)])
        owners.append(owner);views.append(view)
    b.effect('loan.end',[views[0]]);views[0]=b.value('readbuf','borrow.read',[owners[0]])
    code=b.value('u32','call',views,{'function':'f0'})
    raw=[b.value('u8','buffer.load',[views[1],b.const('usize',i)]) for i in range(48)]
    for v in views:b.effect('loan.end',[v])
    for o in owners:b.effect('owner.drop',[o])
    source=('hia-asm.v1 hepta.hia.program.v8 module_policy_reference\n'
        'fn observe() -> (u32,'+','.join(['u8']*48)+') effects(alloc,read,write,trap) entry(b0)\nblock b0()\n'+b.text()
        +'  ret('+','.join([code,*raw])+')\nend\n'+SOURCE.read_text().split('\n',1)[1])
    result=execute_program(assemble_program(source),'observe',[],max_steps=2000000)
    assert result['status']=='returned',result
    code,*raw=result['values'];return code,bytes(raw)


def decl(public=False,extern=False,export=False):return NS(public=public,extern_c=extern,export_c=export)


def unit(types=(),functions=(),imports=(),prefix='Mabc_'):
    return NS(types=dict(types),functions=dict(functions),imports=dict(imports),names={name:prefix+name for name in [*[k for k,v in types],*[k for k,v in functions]]})


def observe(call):
    try:return ('value',call())
    except HeptaError as e:return ('error',e.diagnostic.to_dict())


class ModuleSymbolsSourceTests(unittest.TestCase):
    def test_exact_generated_source_and_independent_VM_before_seed(self):
        from tools.generate_hia_module_symbols import document
        from hepta.hia_agent_assembly import render_assembly
        self.assertEqual(SOURCE.read_text(),render_assembly(document()))
        cases=[(packet(1,[(0,'a','a',1),(0,'a','a',2)]),1,b''),
            (packet(2,[(0,'a','a',1)],[],name='a'),2,b''),
            (packet(3,[(0,'T','renamed_T',1)],[],name='T::V'),0,b'renamed_T::V'),
            (packet(3,[(1,'f','public_f',6)],[('dep',1)],name='dep::f'),0,b'public_f'),
            (packet(3,[(1,'f','private_f',2)],[('dep',1)],name='dep::f'),4,b''),
            (packet(3,[(1,'f','public_f',6)],[('dep',1)],name='dep::f::x'),3,b''),
            (packet(3,[],name='Result::Ok'),0,b'Result::Ok'),
            (packet(3,[],name='missing::x'),5,b'')]
        for wire,status,text in cases:
            with self.subTest(status=status,text=text):
                code,raw=vm(wire);self.assertEqual(code,16+len(text));self.assertEqual(struct.unpack_from('<2Q',raw),(status,len(text)));self.assertEqual(raw[16:code],text)


class NativeModuleSymbolsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Independent semantic execution genuinely precedes seed/native compile.
        code,raw=vm(packet(3,[(0,'T','Mtype',1)],name='T'))
        assert code==21 and raw[16:21]==b'Mtype'
        from tools.qualify_hia_selfhost import build_seed,compile_stage
        cls.tmp=tempfile.TemporaryDirectory(prefix='hia-module-symbols-');cls.root=Path(cls.tmp.name)
        seed,_=build_seed(cls.root)
        first,_=compile_stage(cls.root,'B1',seed,(ROOT/'examples/hia_bootstrap/selfhost.hiaasm').read_bytes(),image_format='seed-shared')
        second,_=compile_stage(cls.root,'B2',first,(ROOT/'examples/hia_bootstrap/selfhost.hiaasm').read_bytes())
        assert first.read_bytes()==second.read_bytes()
        image,cls.compile_receipt=compile_stage(cls.root,'module-symbols',second,SOURCE.read_bytes())
        cls.image=image.read_bytes();cls.native=NativeModuleSymbols(cls.image,sha256(cls.image).hexdigest())
        cls.manifest=cls.root/'manifest.json';cls.manifest.write_text(json.dumps({'schema':SCHEMA,'source_sha256':sha256(SOURCE.read_bytes()).hexdigest(),'image_path':image.name,'image_sha256':sha256(cls.image).hexdigest(),'compiler_sha256':sha256(second.read_bytes()).hexdigest()}))
        cls.selected=installed_module_symbols(str(cls.manifest))

    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()

    def test_all_existing_policy_branches_and_diagnostics_match_independent_reference(self):
        dep=unit(types=[('Public',decl(True)),('Hidden',decl())],functions=[('visible',decl(True)),('hidden',decl()),('foreign',decl(extern=True)),('exported',decl(export=True))])
        local=unit(types=[('T',decl()),('Result',decl())],functions=[('f',decl())],imports=[('dep',dep)])
        queries=['T','T::Variant','T::Variant::field','f','missing','dep','dep::Public','dep::Public::Variant','dep::Public::Variant::field','dep::Hidden','dep::visible','dep::hidden','dep::foreign','dep::exported','dep::visible::invalid','dep::missing','unknown::f','Result::Ok','Result::Ok::field','dep::','dep::::x']
        for role in ('type','term'):
            for query in queries:
                with self.subTest(role=role,query=query):
                    span=Span(2,7,3,4,'actual.hepta')
                    expected=observe(lambda:_resolve_reference(local,query,role,span))
                    self.assertEqual(observe(lambda:self.selected.resolve(local,query,role,span)),expected)
        self.assertEqual(self.selected.resolve(unit(),'Result::Ok','term',Span()),'Result::Ok')

    def test_random_fact_tables_visibility_roles_and_utf8_names(self):
        rng=random.Random(724);names=['a','b','T','Result','é','δ','中文']
        for _ in range(120):
            rng.shuffle(names);dep=unit(types=[(names[0],decl(bool(rng.randrange(2))))],functions=[(names[1],decl(bool(rng.randrange(2)),bool(rng.randrange(2))))],prefix='Mδ_')
            local=unit(types=[(names[2],decl())],functions=[(names[3],decl())],imports=[('lib',dep)])
            for query in [names[2],names[3],names[0],'lib::'+names[0]+'::V','lib::'+names[1],'lib::'+names[1]+'::V',names[2]+'::V','Result::Ok','other::x']:
                role=rng.choice(['type','term']);span=Span(path='random.hepta')
                self.assertEqual(observe(lambda:self.selected.resolve(local,query,role,span)),observe(lambda:_resolve_reference(local,query,role,span)))

    def test_duplicate_declaration_and_alias_admission_are_native(self):
        for kinds in ((1,1),(1,2),(2,2)):
            self.assertEqual(self.native.run(packet(1,[(0,'same','x',kinds[0]),(0,'same','y',kinds[1])]))[0],1)
        local=unit(types=[('T',decl())],functions=[('f',decl())],imports=[('dep',unit())])
        for name in ('T','f','dep'):
            with self.assertRaisesRegex(HeptaError,'Import alias collides'):self.selected.alias(local,name,Span())
        self.assertIsNone(self.selected.alias(local,'fresh',Span()))

    def test_malformed_packet_and_short_capacity_never_publish_partial_output(self):
        valid=packet(3,[(0,'T','renamed',1)],name='T');cases=[b'',valid[:63]]
        for offset,value in ((0,0),(16,(1<<64)-1),(24,(1<<64)-1),(32,0),(40,(1<<64)-1),(48,2),(56,1),(64,1),(104,3),(72,0),(80,(1<<64)-1)):
            wire=bytearray(valid);struct.pack_into('<Q',wire,offset,value);cases.append(bytes(wire))
        for wire in cases:
            source=ctypes.create_string_buffer(wire,max(1,len(wire)));out=ctypes.create_string_buffer(b'Z'*64,64);state=ctypes.create_string_buffer(1)
            code=self.native._entry(source,len(wire),out,64,state,1)
            self.assertEqual(code,0xfffffffd);self.assertEqual(out.raw,b'Z'*64)
        source=ctypes.create_string_buffer(valid);out=ctypes.create_string_buffer(b'Y'*20,20);state=ctypes.create_string_buffer(1)
        self.assertEqual(self.native._entry(source,len(valid),out,20,state,1),0xfffffffe);self.assertEqual(out.raw,b'Y'*20)

    def test_selected_project_path_never_calls_reference_resolver(self):
        from dataclasses import asdict
        with tempfile.TemporaryDirectory(prefix='hia-module-project-') as d:
            root=Path(d);(root/'a.hepta').write_text('pub struct Item { x: u64 } pub fn value() -> u64 effects {} { return 7; }')
            (root/'b.hepta').write_text('import a; pub fn value() -> u64 effects {} { return a::value(); }')
            entry=root/'main.hepta';entry.write_text('import a; import b; fn main() -> i32 effects {} { let x: a::Item = a::Item { x: b::value() }; return x.x as i32; }')
            with patch.dict(os.environ,{'HEPTA_HIA_MODULE_SYMBOLS_MANIFEST':''}):expected=load_project(entry)
            with patch.dict(os.environ,{'HEPTA_HIA_MODULE_SYMBOLS_MANIFEST':str(self.manifest)}),patch('hepta.modules._resolve_reference',side_effect=AssertionError('foreign name authority used')):
                actual=load_project(entry)
            self.assertEqual(asdict(actual),asdict(expected))
            self.assertTrue(actual.unchanged())

    def test_real_private_type_and_duplicate_import_diagnostics_have_original_spans(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'a.hepta').write_text('struct Hidden { x: u64 } fn secret() -> u64 effects {} { return 1; }')
            entry=root/'main.hepta'
            for text in ('import a; import a;', 'import a; fn a() -> Unit effects {} { return; }', 'import a; fn main() -> i32 effects {} { return a::secret() as i32; }', 'import a; fn main(x: a::Hidden) -> i32 effects {} { return 0; }'):
                entry.write_text(text)
                with patch.dict(os.environ,{'HEPTA_HIA_MODULE_SYMBOLS_MANIFEST':''}):expected=observe(lambda:load_project(entry))
                with patch.dict(os.environ,{'HEPTA_HIA_MODULE_SYMBOLS_MANIFEST':str(self.manifest)}),patch('hepta.modules._resolve_reference',side_effect=AssertionError('foreign resolver')):
                    self.assertEqual(observe(lambda:load_project(entry)),expected)

    def test_concurrent_calls_have_private_scratch(self):
        local=unit(types=[('T',decl())])
        with ThreadPoolExecutor(max_workers=8) as pool:
            got=list(pool.map(lambda _:self.selected.resolve(local,'T::V','term',Span()),range(64)))
        self.assertEqual(got,['Mabc_T::V']*64)

    def test_bad_explicit_manifest_is_not_a_reference_fallback(self):
        with tempfile.TemporaryDirectory() as d:
            entry=Path(d)/'main.hepta';entry.write_text('fn main() -> i32 effects {} { return 0; }')
            with patch.dict(os.environ,{'HEPTA_HIA_MODULE_SYMBOLS_MANIFEST':str(Path(d)/'missing')}),patch('hepta.modules._resolve_reference',side_effect=AssertionError('fallback')):
                with self.assertRaises(FileNotFoundError):load_project(entry)


if __name__=='__main__':unittest.main()
