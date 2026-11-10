"""Nominal generic graph decisions through independent VM and native successors."""
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
from hepta.ast import Type, Struct, Enum, EnumVariant, Param, HeptaError, Span
from hepta.checker import _contains_capability_reference as _contains_capability
from hepta.borrowed_storage import _contains_storage_reference as contains_storage
from hepta.hia_type_graph_native import (SOURCE, SCHEMA, MAGIC, WORKSPACE, OWNED_WORKSPACE, OWNED_OUTPUT,
    NativeTypeGraph, GraphProfileLimit, packet, materialize, materialize_owned,
    VALIDATION_WORKSPACE, VALIDATION_OUTPUT, materialize_validation)
from tools.generate_hia_type_graph import document
ROOT=Path(__file__).resolve().parents[1]


def record(name,fields,params=(),lifetimes=()):
    return Struct(name,[Param('f'+str(i),t) for i,t in enumerate(fields)],
        type_params=params,lifetime_params=lifetimes)


def literal_cases():
    u=Type('u64');buffer=Type('Buffer',(u,));t=Type('T')
    box=record('Box',[t],('T',))
    loop=record('Loop',[Type('Loop',(Type('Buffer',(t,)),)),t],('T',))
    # Raw stored-borrow classification deliberately does NOT substitute T.
    life=record('Life',[Type('T',lifetimes=('a',))],('T',))
    duplicate=record('D',[t],('T','T'))
    length=record('L',[Type('T',length=0)],('T',))
    declarations={d.name:d for d in (box,loop,life,duplicate,length)}
    return [
        (Type('Box',(buffer,)),declarations,{}, {'Buffer'},frozenset(),1,True),
        (Type('Loop',(u,)),declarations,{}, {'Buffer'},frozenset(),1,True),
        (Type('ref_read',(buffer,)),{}, {}, {'Buffer'},frozenset(),1,True),
        (Type('ref_read',(buffer,)),{}, {}, {'Buffer','ref_mut'},frozenset(),1,False),
        (Type('ref_mut',(u,)),{}, {}, {'ref_mut'},frozenset(),1,True),
        (Type('D',(buffer,u)),declarations,{}, {'T'},frozenset(),1,False),
        (Type('D',(u,buffer)),declarations,{}, {'T'},frozenset(),1,False),
        (Type('L',(u,)),declarations,{}, {'T'},frozenset(),1,True),
        (Type('Life',(u,)),declarations,{}, set(),frozenset(),2,True),
        (Type('Box',(buffer,)),declarations,{}, {'Buffer'},frozenset({'Box'}),1,True),
        (Type('Box',(u,)),declarations,{}, {'T'},frozenset({'Box'}),1,False),
        (Type('Box',(u,)),declarations,{}, {'T'},frozenset(),1,False),
    ]


def vm_literals():
    from tests.test_hia_json_decode_native import vm_arena
    for typ,structs,enums,names,seen,mode,wanted in literal_cases():
        graph=packet(typ,structs,enums,names=names,seen=seen,mode=mode)
        size,raw=vm_arena(graph.wire,source_path=SOURCE,sizes=(32,WORKSPACE))
        expected=struct.pack('<4Q',MAGIC+1,int(wanted),mode,0)
        assert size==32 and raw==expected,(typ,names,mode,size,raw,expected)
    u=Type('u64');buffer=Type('Buffer',(u,));array=Type('array',(buffer,),2)
    graph=packet(array,{},names={'Buffer','Task','TaskGroup','ref_mut'},mode=3)
    size,raw=vm_arena(graph.wire,source_path=SOURCE,sizes=(240,OWNED_WORKSPACE))
    expected=struct.pack('<4Q',MAGIC+2,1,3,2)+struct.pack('<Q',2)
    expected+=struct.pack('<9Q',0,0,0,1,0,1,2,1,1)+struct.pack('<2Q',0,1)
    assert size==len(expected) and raw==expected,(size,raw,expected)
    assert materialize_owned(raw,graph)==[array]
    box=record('Box',[Type('array',(Type('T',lifetimes=('discarded',)),),2)],('T',))
    graph=packet(Type('Box',(buffer,)),{'Box':box},names={'Buffer','ref_mut'},mode=3)
    size,raw=vm_arena(graph.wire,source_path=SOURCE,sizes=(240,OWNED_WORKSPACE))
    assert size==128 and materialize_owned(raw,graph)==[array],(size,raw)

    # Independent VM checks the new controller's return/diagnostic asymmetry
    # and the native-selected missing generic-argument sentinel before B0.
    graph=packet(Type('u64',lifetimes=('bad',)),{},mode=4)
    size,raw=vm_arena(graph.wire,source_path=SOURCE,sizes=(240,VALIDATION_WORKSPACE))
    expected=struct.pack('<8Q',MAGIC+3,1,2,2,0,4,0,0)
    expected+=struct.pack('<8Q',1,0,0,0,2,1,0,0)+struct.pack('<6Q',0,0,0,0,0,0)
    assert size==len(expected) and raw==expected,(size,raw,expected)
    assert materialize_validation(raw,graph)==(True,[('E_LIFETIME_ARITY','u64 expects 0 lifetime argument(s)'),
        ('E_LIFETIME_SCOPE',"undeclared or unsupported lifetime 'bad")],[])
    graph=packet(Type('$generic-arguments',(u,)),{},mode=5,generic_params=('T','U'))
    size,raw=vm_arena(graph.wire,source_path=SOURCE,sizes=(240,VALIDATION_WORKSPACE))
    good,messages,mapping=materialize_validation(raw,graph)
    assert size==184 and good and messages==[('E_GENERIC_ARITY','expected 2 explicit type argument(s), found 1')]
    assert mapping==[('T',u),('U',None)]


class TypeGraphSourceTests(unittest.TestCase):
    def test_malformed_container_types_render_without_hiding_extra_arguments(self):
        from hepta.checker import _Checker
        from hepta.parser import parse
        u=Type('u64');b=Type('Buffer',(u,))
        for name in ('array','slice','raw_const','raw_mut'):
            self.assertEqual(str(Type(name)),name)
            self.assertEqual(str(Type(name,(u,b))),name+'<u64, Buffer<u64>>')
            checker=_Checker(parse(''))
            self.assertFalse(checker.valid_type(Type(name),Span()))
            self.assertEqual(checker.result.diagnostics[-1].code,'E_TYPE_FORM')

    def test_independent_VM_literals_before_any_native_seed(self):
        from hepta.hia_agent_assembly import render_assembly
        self.assertEqual(SOURCE.read_text(),render_assembly(document()))
        vm_literals()


class TypeGraphNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        vm_literals()
        from tools.qualify_hia_selfhost import build_seed,compile_stage
        cls.temporary=tempfile.TemporaryDirectory(prefix='hia-type-graph-')
        cls.folder=Path(cls.temporary.name)
        seed,_=build_seed(cls.folder)
        source=(ROOT/'examples/hia_bootstrap/selfhost.hiaasm').read_bytes()
        b1,_=compile_stage(cls.folder,'B1',seed,source,image_format='seed-shared')
        b2,_=compile_stage(cls.folder,'B2',b1,source)
        assert b1.read_bytes()==b2.read_bytes()
        image,cls.receipt=compile_stage(cls.folder,'type-graph',b2,SOURCE.read_bytes())
        raw=image.read_bytes();cls.native=NativeTypeGraph(raw,sha256(raw).hexdigest())
        cls.manifest=cls.folder/'manifest.json'
        cls.manifest.write_text(json.dumps({'schema':SCHEMA,'source_sha256':sha256(SOURCE.read_bytes()).hexdigest(),
            'image_path':image.name,'image_sha256':sha256(raw).hexdigest(),'compiler_sha256':sha256(b2.read_bytes()).hexdigest()}))

    @classmethod
    def tearDownClass(cls):cls.temporary.cleanup()

    def compare(self,typ,structs,enums=None,names=frozenset(),seen=frozenset(),mode=1):
        enums=enums or {}
        expected=(_contains_capability(typ,names,structs,enums,seen) if mode==1
            else contains_storage(typ,structs,enums))
        graph=packet(typ,structs,enums,names=names,seen=seen,mode=mode)
        self.assertEqual(self.native.query(graph),expected,(typ,names,seen,mode))

    def owned_compare(self,typ,structs,enums=None,owned=frozenset()):
        from hepta.checker import _Checker,LINEAR
        from hepta.parser import parse
        checker=_Checker(parse(''));checker.structs=structs;checker.enums=enums or {}
        checker.owned_type_params=set(owned)
        expected=checker._valid_owned_payload_shapes_reference(typ,Span())
        graph=packet(typ,structs,enums,names=LINEAR|set(owned)|{'ref_mut'},mode=3)
        diagnostics=self.native.owned_shapes(graph)
        self.assertEqual(not diagnostics,expected)
        self.assertEqual(['instantiated payload '+str(t)+' hides resources in an unsupported container' for t in diagnostics],
            [d.message for d in checker.result.diagnostics])
        return graph,diagnostics

    def test_owned_instantiation_recursive_masks_arities_and_native_diagnostic_types(self):
        u=Type('u64');t=Type('T');buffer=Type('Buffer',(u,));arr=lambda x:Type('array',(x,),2)
        declarations={'Box':record('Box',[arr(t)],('T',)),
            'S':record('S',[arr(t),Type('S',(buffer,))],('T',))}
        self.owned_compare(Type('Box',(buffer,)),declarations)
        self.owned_compare(Type('S',(u,)),declarations)
        self.owned_compare(Type('S',(buffer,)),declarations)
        d={'Root':record('Root',[Type('S',(u,)),Type('S',(u,u))]),
           'S':record('S',[arr(Type('U'))],('T','U'))}
        self.owned_compare(Type('Root'),d,owned={'U'})
        params=tuple('T'+str(i) for i in range(128))
        self.owned_compare(Type('Wide',(u,)*127+(buffer,)),{'Wide':record('Wide',[arr(Type('T127'))],params)})
        for name in ('array','slice','Buffer','raw_const','raw_mut'):
            self.owned_compare(Type(name,(buffer,)),{})
        # Length prevents placeholder replacement; placeholder lifetimes do not.
        for placeholder in (Type('T',length=0),Type('T',lifetimes=('discarded',))):
            self.owned_compare(Type('Box',(buffer,)),{'Box':record('Box',[arr(placeholder)],('T',))})
        for args in ((buffer,u),(u,buffer)):
            self.owned_compare(Type('Box',args),{'Box':record('Box',[arr(t)],('T','T'))})
        e={'E':Enum('E',[EnumVariant('First',[arr(t)]),EnumVariant('Second',[Type('raw_const',(t,))])],('T',))}
        self.owned_compare(Type('E',(buffer,)),{},e)
        self.owned_compare(Type('ref_read',(arr(buffer),)),{})
        self.owned_compare(Type('Unknown',(arr(buffer),)),{})

    def test_four_hundred_owned_graphs_match_original_phase_and_diagnostic_order(self):
        rng=random.Random(0x0d2026)
        alphabet=['u64','Buffer','Task','Cancellation','Sender','ref_read','ref_mut','T','U','A','B','C','array','slice','raw_const','raw_mut']
        def typ(depth=0):
            args=tuple(typ(depth+1) for _ in range(rng.randrange(3))) if depth<2 else ()
            return Type(rng.choice(alphabet),args,rng.choice([None,None,0,2,True]),('a',) if rng.randrange(9)==0 else ())
        for i in range(400):
            s={n:record(n,[typ() for _ in range(rng.randrange(4))],rng.choice([(),('T',),('T','U'),('T','T')])) for n in ('A','B')}
            e={'C':Enum('C',[EnumVariant('V',[typ() for _ in range(rng.randrange(3))])],type_params=rng.choice([(),('T',),('T','U')]))}
            self.owned_compare(Type(rng.choice(['A','B','C']),tuple(typ() for _ in range(rng.randrange(3)))),s,e,
                owned=set(rng.sample(['T','U'],rng.randrange(3))))

    def test_owned_buffers_context_limits_and_result_graph_refusals(self):
        u=Type('u64');buffer=Type('Buffer',(u,));typ=Type('array',(buffer,),2)
        graph,_=self.owned_compare(typ,{})
        for capacity,work,wanted in ((31,OWNED_WORKSPACE,0xfffffffe),(OWNED_OUTPUT,OWNED_WORKSPACE-1,0xfffffffd)):
            s=ctypes.create_string_buffer(graph.wire,len(graph.wire));o=ctypes.create_string_buffer(b'\xa5'*(capacity+8),capacity+8)
            w=ctypes.create_string_buffer(b'\x5a'*(work+8),work+8)
            self.assertEqual(self.native._entry(s,len(graph.wire),o,capacity,w,work),wanted)
            self.assertEqual(o.raw,b'\xa5'*(capacity+8));self.assertEqual(w.raw[work:],b'\x5a'*8)
            self.assertEqual(s.raw,graph.wire)
        raw=struct.pack('<4Q',MAGIC+2,1,1,0)+struct.pack('<Q',0)+struct.pack('<3Q',0,0,0)
        for offset,value in ((0,0),(8,8193),(16,32769),(24,65537),(32,1),(40,8192),(48,1),(56,1)):
            broken=bytearray(raw);struct.pack_into('<Q',broken,offset,value)
            with self.assertRaises(RuntimeError):materialize_owned(bytes(broken),graph)

    def test_owned_diagnostic_clone_limit_and_atomic_profile_exhaustion(self):
        from hepta.checker import LINEAR
        u=Type('u64');b=Type('Buffer',(Type('W',(u,)),));array=Type('array',(b,),2)
        p=packet(Type('G'),{'G':record('G',[array]*8192)},names=LINEAR|{'ref_mut'},mode=3)
        values=self.native.owned_shapes(p)
        # Exactly 8,192 diagnostics and 32,768 postorder nodes, not a reduced cap.
        self.assertEqual(len(values),8192);self.assertTrue(all(value==array for value in values))
        too_deep=Type('array',(Type('Buffer',(Type('W',(Type('X',(u,)),)),)),),2)
        clone_over=packet(Type('G'),{'G':record('G',[too_deep]*8192)},names=LINEAR|{'ref_mut'},mode=3)
        d={'G':record('G',[Type('D',(u,)),Type('D',(Type('Buffer',(u,)),))]),
           'D':record('D',[array]*8190,('T',))}
        diagnostic_over=packet(Type('G'),d,names=LINEAR|{'ref_mut'},mode=3)
        for graph in (clone_over,diagnostic_over):
            s=ctypes.create_string_buffer(graph.wire,len(graph.wire))
            o=ctypes.create_string_buffer(b'\xa5'*(OWNED_OUTPUT+8),OWNED_OUTPUT+8)
            w=ctypes.create_string_buffer(b'\x5a'*(OWNED_WORKSPACE+8),OWNED_WORKSPACE+8)
            self.assertEqual(self.native._entry(s,len(graph.wire),o,OWNED_OUTPUT,w,OWNED_WORKSPACE),0xfffffffc)
            self.assertEqual(o.raw,b'\xa5'*(OWNED_OUTPUT+8));self.assertEqual(w.raw[OWNED_WORKSPACE:],b'\x5a'*8)
            self.assertEqual(s.raw,graph.wire)

    def test_owned_private_concurrency_and_selected_error_fallback_boundary(self):
        from hepta.checker import _Checker,LINEAR
        from hepta.parser import parse
        u=Type('u64');b=Type('Buffer',(u,));array=lambda t:Type('array',(t,),2)
        packets=[packet(array(b if i%2 else u),{},names=LINEAR|{'ref_mut'},mode=3) for i in range(32)]
        with ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(list(pool.map(self.native.owned_shapes,packets)),[[array(b)] if i%2 else [] for i in range(32)])
        c=_Checker(parse(''))
        with patch.dict('os.environ',{'HEPTA_HIA_TYPE_GRAPH_MANIFEST':str(self.manifest)}):
            with patch.object(NativeTypeGraph,'owned_shapes',side_effect=RuntimeError('invalid native result')):
                with self.assertRaisesRegex(RuntimeError,'invalid native result'):c.valid_owned_payload_shapes(array(b),Span())
            self.assertEqual(c.result.diagnostics,[])
            with patch.object(NativeTypeGraph,'owned_shapes',side_effect=GraphProfileLimit('explicit native scratch bound')):
                self.assertFalse(c.valid_owned_payload_shapes(array(b),Span()))
            self.assertEqual(len(c.result.diagnostics),1)
        with patch.dict('os.environ',{'HEPTA_HIA_TYPE_GRAPH_MANIFEST':'missing-manifest'}):
            self.assertTrue(c.valid_owned_payload_shapes(Type('Unknown',tuple(Type('x'+str(i)) for i in range(8193))),Span()))

    def test_literal_decisions_generics_cycles_references_and_storage(self):
        for typ,s,e,n,seen,mode,wanted in literal_cases():
            self.assertEqual(self.native.query(packet(typ,s,e,names=n,seen=seen,mode=mode)),wanted)
            self.compare(typ,s,e,n,seen,mode)
        self.assertEqual(self.receipt['forbidden_compiler_modules_loaded'],[])
        # Registry keys, not the nominal object's name, control lookup; structs win.
        s={'Key':record('Different',[Type('Resource')])}
        e={'Key':Enum('Key',[EnumVariant('V',[Type('Other')])])}
        self.compare(Type('Key'),s,e,{'Resource'})
        self.compare(Type('Key'),s,e,{'Other'})

    def validation_compare(self,typ,structs,enums=None,*,params=frozenset(),owned=frozenset(),lifetimes=frozenset(),body=False,flags=0):
        from hepta.checker import _Checker,LINEAR
        from hepta.parser import parse
        c=_Checker(parse(''));c.structs=structs;c.enums=enums or {};c.type_params=set(params)
        c.owned_type_params=set(owned);c.lifetime_params=set(lifetimes);c.in_body=body
        with patch.dict('os.environ',{'HEPTA_HIA_TYPE_GRAPH_MANIFEST':''}):
            wanted=c._valid_type_reference(typ,Span(),allow_slice=bool(flags&1),allow_cancellation=bool(flags&2),allow_sender=bool(flags&4),allow_reference=bool(flags&8))
        graph=packet(typ,structs,enums or {},names=LINEAR|set(owned)|{'ref_mut'},mode=4,
            type_params=set(params),lifetime_params=set(lifetimes),in_body=body,flags=flags)
        good,messages,mapping=self.native.validate_type(graph)
        self.assertEqual((good,messages,mapping),(wanted,[(d.code,d.message) for d in c.result.diagnostics],[]),
            (typ,params,owned,lifetimes,body,flags))
        return graph

    def generic_compare(self,params,args,structs,enums=None,*,bounds=None,allow=False,type_params=frozenset(),owned=frozenset(),lifetimes=frozenset(),body=False):
        from hepta.checker import _Checker,LINEAR,ERROR
        from hepta.parser import parse
        c=_Checker(parse(''));c.structs=structs;c.enums=enums or {};c.type_params=set(type_params)
        c.owned_type_params=set(owned);c.lifetime_params=set(lifetimes);c.in_body=body
        with patch.dict('os.environ',{'HEPTA_HIA_TYPE_GRAPH_MANIFEST':''}):
            wanted=c._generic_arguments_reference(params,args,Span(),allow_owned=allow,bounds=bounds)
        graph=packet(Type('$generic-arguments',args),structs,enums or {},names=LINEAR|set(owned)|{'ref_mut'},mode=5,
            type_params=set(type_params),lifetime_params=set(lifetimes),in_body=body,generic_params=params,bounds=bounds,allow_owned=allow)
        good,messages,mapping=self.native.validate_type(graph)
        self.assertTrue(good)
        self.assertEqual(messages,[(d.code,d.message) for d in c.result.diagnostics],(params,args,bounds,allow))
        self.assertEqual({name:ERROR if value is None else value for name,value in mapping},wanted)
        return graph

    def test_complete_type_validity_branch_order_lifetimes_and_return_values(self):
        from hepta.checker import PRIMITIVES,IO_OWNER_TYPES
        u=Type('u64');t=Type('T');b=Type('Buffer',(u,));arr=lambda x:Type('array',(x,),2)
        declarations={'Box':record('Box',[arr(t)],('T',)),
            'View':record('View',[Type('ref_read',(u,),lifetimes=('a',))],lifetimes=('a',)),
            'S':record('S',[Type('S',(b,)),arr(t)],('T',)),
            'Weird':record('Weird',[t],('T',))}
        enums={'E':Enum('E',[EnumVariant('V',[t])],type_params=('T',))}
        # Nonempty nominal parameter rows must never overwrite caller scope.
        self.validation_compare(t,declarations,enums,params={'T'})
        for name in sorted(PRIMITIVES|IO_OWNER_TYPES|{'TaskGroup','Sender','Cancellation','array','slice','Buffer','Task','raw_const','raw_mut','T','missing','é😀'}):
            for args,length in (((),None),((u,),None),((u,b),0),((u,),True),((u,),-1),((u,),0)):
                for flags in (0,15):
                    self.validation_compare(Type(name,args,length,('a','_','bad')),declarations,enums,
                        params={'T'},owned={'T'},lifetimes={'a'},body=True,flags=flags)
        for typ in (Type('Box',(u,)),Type('Box',(b,)),Type('Box',(u,),2,('bad',)),
                Type('S',(u,)),Type('E',(b,)),Type('View',lifetimes=('a',)),
                Type('ref_read',(Type('IoReactor'),),lifetimes=('a',)),
                Type('ref_mut',(Type('View',lifetimes=('a',)),),lifetimes=('bad',))):
            for flags in (0,1,8,15):self.validation_compare(typ,declarations,enums,lifetimes={'a'},flags=flags)

    def test_generic_arguments_bounds_duplicate_mapping_and_native_missing_selection(self):
        u=Type('u64');b=Type('Buffer',(u,));t=Type('T')
        declarations={'D':record('D',[t],('T','T')),'V':record('V',[],lifetimes=('a',))}
        for params in ((),('T',),('T','U'),('T','T')):
            for args in ((),(u,),(b,u),(u,b),(t,Type('Task',(u,)),Type('V',lifetimes=('a',)),Type('slice',(u,)))):
                for bounds in (None,{'T':'Owned'},{'T':'Other','U':'Owned'}):
                    for allow in (False,True):
                        self.generic_compare(params,args,declarations,bounds=bounds,allow=allow,type_params={'T'},owned={'T'},lifetimes={'a'})

    def test_four_hundred_random_complete_types_and_generic_arguments(self):
        rng=random.Random(0x7a9e4040)
        alphabet=['u64','bool','Buffer','Task','TaskGroup','Cancellation','Sender','IoReactor','IoRequest',
            'array','slice','raw_const','raw_mut','ref_read','ref_mut','T','U','A','B','C','é😀']
        def typ(depth=0):
            name=rng.choice(alphabet)
            args=tuple(typ(depth+1) for _ in range(rng.randrange(3))) if depth<3 else ()
            return Type(name,args,rng.choice([None,None,None,0,1,-1,True]),
                rng.choice([(),(),('a',),('_',),('bad','a')]))
        for i in range(400):
            declarations={n:record(n,[typ() for _ in range(rng.randrange(3))],rng.choice([(),('T',),('T','T')]),
                rng.choice([(),('a',)])) for n in ('A','B')}
            enums={'C':Enum('C',[EnumVariant('V',[typ()])],type_params=('T',))}
            params=set(rng.sample(['T','U'],rng.randrange(3)));owned=set(rng.sample(['T','U'],rng.randrange(3)))
            lifetimes=set(rng.sample(['a','_'],rng.randrange(3)));body=bool(rng.randrange(2))
            root=typ();self.validation_compare(root,declarations,enums,params=params,owned=owned,lifetimes=lifetimes,body=body,flags=rng.randrange(16))
            gparams=rng.choice([(),('T',),('T','U'),('T','T')]);args=tuple(typ() for _ in range(rng.randrange(4)))
            self.generic_compare(gparams,args,declarations,enums,bounds={'T':rng.choice(['Copy','Owned','Other']),'U':'Owned'},
                allow=bool(rng.randrange(2)),type_params=params,owned=owned,lifetimes=lifetimes,body=body)

    def test_type_validation_guards_atomic_exhaustion_and_private_concurrency(self):
        from hepta.checker import LINEAR
        u=Type('u64');graph=packet(u,{},mode=4,names=LINEAR|{'ref_mut'})
        # Guarded writes for malformed config, undersized scratch/output,
        # and real clone/diagnostic exhaustion, not mocked boundary outcomes.
        h=struct.unpack_from('<16Q',graph.wire);cfg=h[13]+sum(h[i] for i in (4,6,7,8))*8
        bad=[]
        for offset,value in ((cfg,8193),(cfg+16,2),(cfg+24,16),(cfg+32,1),(cfg+40,1),(cfg+48,1)):
            wire=bytearray(graph.wire);struct.pack_into('<Q',wire,offset,value);bad.append(bytes(wire))
        for wire,capacity,work,wanted in [(b,64,VALIDATION_WORKSPACE,0xfffffffd) for b in bad]+[
                (graph.wire,64,VALIDATION_WORKSPACE-1,0xfffffffd),(graph.wire,63,VALIDATION_WORKSPACE,0xfffffffe)]:
            src=ctypes.create_string_buffer(wire,len(wire));out=ctypes.create_string_buffer(b'\xa5'*(capacity+8),capacity+8)
            scratch=ctypes.create_string_buffer(b'\x5a'*(work+8),work+8)
            self.assertEqual(self.native._entry(src,len(wire),out,capacity,scratch,work),wanted)
            self.assertEqual(out.raw,b'\xa5'*(capacity+8));self.assertEqual(scratch.raw[work:],b'\x5a'*8)
            self.assertEqual(src.raw,wire)
        exhausted=[packet(Type('S',(u,)*32768),{'S':record('S',[])},mode=4,names=LINEAR|{'ref_mut'}),
            packet(Type('u64',lifetimes=('bad',)*32768),{},mode=4,names=LINEAR|{'ref_mut'})]
        for p in exhausted:
            src=ctypes.create_string_buffer(p.wire,len(p.wire));out=ctypes.create_string_buffer(b'\xa5'*(VALIDATION_OUTPUT+8),VALIDATION_OUTPUT+8)
            scratch=ctypes.create_string_buffer(b'\x5a'*(VALIDATION_WORKSPACE+8),VALIDATION_WORKSPACE+8)
            self.assertEqual(self.native._entry(src,len(p.wire),out,VALIDATION_OUTPUT,scratch,VALIDATION_WORKSPACE),0xfffffffc)
            self.assertEqual(out.raw,b'\xa5'*(VALIDATION_OUTPUT+8));self.assertEqual(scratch.raw[VALIDATION_WORKSPACE:],b'\x5a'*8)
            with self.assertRaises(GraphProfileLimit):self.native.validate_type(p)
        deep=u
        for _ in range(256):deep=Type('raw_const',(deep,))
        self.assertEqual(self.native.validate_type(packet(deep,{},mode=4,names=LINEAR|{'ref_mut'})),(True,[],[]))
        values=[packet(Type('u64',lifetimes=('bad',) if i%2 else ()),{},mode=4,names=LINEAR|{'ref_mut'}) for i in range(32)]
        expected=[self.native.validate_type(p) for p in values]
        with ThreadPoolExecutor(max_workers=8) as pool:self.assertEqual(list(pool.map(self.native.validate_type,values)),expected)
        for raw in (b'',struct.pack('<8Q',MAGIC+3,2,0,0,0,4,0,0),struct.pack('<8Q',MAGIC+3,1,0,0,0,5,0,0)):
            with self.assertRaises(RuntimeError):materialize_validation(raw,graph)

    def test_selected_complete_type_and_generics_disable_all_original_semantics(self):
        from hepta.checker import _Checker,ERROR
        from hepta.parser import parse
        u=Type('u64');b=Type('Buffer',(u,));t=Type('T')
        c=_Checker(parse(''));c.structs={'S':record('S',[Type('array',(t,),2)],('T',))};c.enums={}
        with patch.dict('os.environ',{'HEPTA_HIA_TYPE_GRAPH_MANIFEST':str(self.manifest)}):
            with patch.object(c,'_valid_type_reference',side_effect=AssertionError('foreign valid_type')), \
                    patch.object(c,'_generic_arguments_reference',side_effect=AssertionError('foreign generics')), \
                    patch.object(c,'_valid_owned_payload_shapes_reference',side_effect=AssertionError('foreign owned shapes')), \
                    patch.object(c,'contains_linear',side_effect=AssertionError('host linear')), \
                    patch.object(c,'contains_capability',side_effect=AssertionError('host capability')), \
                    patch('hepta.checker.contains_storage',side_effect=AssertionError('host storage')), \
                    patch('hepta.checker.substitute_type',side_effect=AssertionError('host substitution')):
                self.assertFalse(c.valid_type(Type('S',(b,)),Span()))
                self.assertEqual(c.generic_arguments(('T','U'),(b,),Span(),bounds={'T':'Owned'}),{'T':b,'U':ERROR})
        self.assertEqual([(d.code,d.message) for d in c.result.diagnostics],[
            ('E_NESTED_LINEAR','instantiated payload [Buffer<u64>; 2] hides resources in an unsupported container'),
            ('E_GENERIC_ARITY','expected 2 explicit type argument(s), found 1')])
        with patch.dict('os.environ',{'HEPTA_HIA_TYPE_GRAPH_MANIFEST':str(self.manifest)}):
            before=list(c.result.diagnostics)
            with patch.object(NativeTypeGraph,'validate_type',side_effect=RuntimeError('broken native result')):
                with self.assertRaisesRegex(RuntimeError,'broken native result'):c.valid_type(u,Span())
                with self.assertRaisesRegex(RuntimeError,'broken native result'):c.generic_arguments(('T',),(u,),Span())
            self.assertEqual(c.result.diagnostics,before)
            with patch.object(NativeTypeGraph,'validate_type',side_effect=GraphProfileLimit('explicit declared boundary')):
                self.assertTrue(c.valid_type(u,Span()))
                self.assertEqual(c.generic_arguments(('T',),(u,),Span()),{'T':u})

    def test_four_hundred_random_nominal_generic_graphs(self):
        rng=random.Random(0x7a9e2026)
        alphabet=['u64','Buffer','Task','Cancellation','Sender','ref_read','ref_mut','T','U','A','B','C','é😀']
        def typ(depth=0):
            name=rng.choice(alphabet)
            args=tuple(typ(depth+1) for _ in range(rng.randrange(3))) if depth<2 else ()
            return Type(name,args,rng.choice([None,None,None,0,1,True]),
                ('a',) if rng.randrange(8)==0 else ())
        for i in range(400):
            s={n:record(n,[typ() for _ in range(rng.randrange(4))],rng.choice([(),('T',),('T','U'),('T','T')]),
                ('a',) if rng.randrange(8)==0 else ()) for n in ('A','B')}
            e={'C':Enum('C',[EnumVariant('V',[typ() for _ in range(rng.randrange(3))])],
                type_params=rng.choice([(),('T',),('T','U')]))}
            root=typ();names=set(rng.sample(alphabet,rng.randrange(5)))
            self.compare(root,s,e,names,frozenset(rng.sample(alphabet,rng.randrange(3))))
            self.compare(root,s,e,mode=2)

    def test_all_graph_bounds_and_private_concurrent_workspace(self):
        u=Type('u64')
        self.compare(Type('Aggregate',tuple(Type('n'+str(i)) for i in range(8191))),{})
        self.compare(Type('Aggregate',tuple([u]*32768)),{})
        declarations={'N'+str(i):record('N'+str(i),[Type('N'+str(i+1))] if i<511 else [u]) for i in range(512)}
        self.compare(Type('N0'),declarations,names={'absent'})
        self.compare(Type('S'),{'S':record('S',[u]*8192,('T',)*4096)},names={'absent'})
        params=tuple('T'+str(i) for i in range(8))
        declarations={'N'+str(i):record('N'+str(i),
            [Type('N'+str(i+1),tuple(Type(t) for t in params))] if i<511 else [Type('T0')],params)
            for i in range(512)}
        self.compare(Type('N0',(u,)*8),declarations,names={'missing'})
        # Exactly 8,192 symbols, then the exact one-MiB wire boundary.
        self.compare(u,{},names={'u64'}|{'q'+str(i) for i in range(8191)})
        short=packet(Type('x'),{})
        long_type=Type('x'*((1<<20)-len(short.wire)+1))
        full=packet(long_type,{})
        self.assertEqual(len(full.wire),1<<20);self.assertFalse(self.native.query(full))
        with self.assertRaises(GraphProfileLimit):packet(Type(long_type.name+'x'),{})
        values=[packet(Type('ref_read',(Type('Buffer',(u,)),)),{},names=({'Buffer'} if i%2 else {'Buffer','ref_mut'})) for i in range(64)]
        with ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(list(pool.map(self.native.query,values)),[bool(i%2) for i in range(64)])
        for root,s in ((Type('Aggregate',tuple(Type('n'+str(i)) for i in range(8192))),{}),
                (Type('Aggregate',tuple([u]*32769)),{}),(u,{**declarations,'extra':record('extra',[])}),
                (u,{'S':record('S',[u]*8193)}),(u,{'S':record('S',[],('T',)*4097)})):
            with self.assertRaises(GraphProfileLimit):packet(root,s)

    def test_malformed_input_and_buffers_refuse_without_output_publication(self):
        p=packet(Type('u64'),{})
        bad=[]
        for offset,value in ((0,0),(8,0),(16,0),(16,8193),(24,513),(32,32769),(40,0),(40,8193),
                (48,4097),(56,8193),(64,8193),(72,8193),(80,1),(88,0),(96,0),(104,0),(112,0),(120,0),
                (128,100),(136,1),(144,1),(152,1),(160,1),(168,3),(176,1),(184,1)):
            wire=bytearray(p.wire);struct.pack_into('<Q',wire,offset,value);bad.append(bytes(wire))
        for wire,capacity,work,wanted in [(x,32,WORKSPACE,0xfffffffd) for x in bad]+[
                (p.wire[:127],32,WORKSPACE,0xfffffffd),(p.wire,32,WORKSPACE-1,0xfffffffd),
                (p.wire,31,WORKSPACE,0xfffffffe)]:
            s=ctypes.create_string_buffer(wire,len(wire));o=ctypes.create_string_buffer(b'\xa5'*(capacity+8),capacity+8)
            w=ctypes.create_string_buffer(b'\x5a'*(work+8),work+8)
            self.assertEqual(self.native._entry(s,len(wire),o,capacity,w,work),wanted,(len(wire),capacity,work))
            self.assertEqual(o.raw,b'\xa5'*(capacity+8));self.assertEqual(w.raw[work:],b'\x5a'*8)
            self.assertEqual(s.raw,wire)
        for raw in (b'',struct.pack('<4Q',MAGIC+1,2,1,0),struct.pack('<4Q',MAGIC+1,1,2,0)):
            with self.assertRaises(RuntimeError):materialize(raw,1)

    def test_actual_source_callers_without_foreign_queries_or_owned_shape_phase(self):
        from hepta.parser import parse
        from hepta.checker import check
        programs=[]
        paths=sorted((ROOT/'tests').rglob('*.hepta'))+sorted((ROOT/'examples').rglob('*.hepta'))
        for path in paths:
            try:program=parse(path.read_text(),str(path))
            except HeptaError:continue
            programs.append(program)
        self.assertGreaterEqual(len(programs),81)
        with patch.dict('os.environ',{'HEPTA_HIA_TYPE_GRAPH_MANIFEST':''}):
            expected=[check(p) for p in programs]
        with patch.dict('os.environ',{'HEPTA_HIA_TYPE_GRAPH_MANIFEST':str(self.manifest)}):
            with patch('hepta.checker._contains_capability_reference',side_effect=AssertionError('foreign capability graph')), \
                    patch('hepta.borrowed_storage._contains_storage_reference',side_effect=AssertionError('foreign storage graph')), \
                    patch('hepta.checker._Checker._valid_owned_payload_shapes_reference',side_effect=AssertionError('foreign owned shapes')), \
                    patch('hepta.checker._Checker._valid_type_reference',side_effect=AssertionError('foreign type validity')), \
                    patch('hepta.checker._Checker._generic_arguments_reference',side_effect=AssertionError('foreign generic arguments')):
                actual=[check(p) for p in programs]
        self.assertEqual(actual,expected)

    def test_selected_owned_phase_without_host_substitution_or_linear_decisions(self):
        from hepta.checker import _Checker
        from hepta.parser import parse
        u=Type('u64');b=Type('Buffer',(u,));t=Type('T')
        declarations={'S':record('S',[Type('array',(t,),2),Type('S',(b,))],('T',))}
        c=_Checker(parse(''));c.structs=declarations;c.enums={}
        with patch.dict('os.environ',{'HEPTA_HIA_TYPE_GRAPH_MANIFEST':str(self.manifest)}):
            with patch.object(c,'_valid_owned_payload_shapes_reference',side_effect=AssertionError('foreign owned phase')), \
                    patch.object(c,'contains_linear',side_effect=AssertionError('host linear decision')), \
                    patch('hepta.checker.substitute_type',side_effect=AssertionError('host generic substitution')):
                self.assertFalse(c.valid_owned_payload_shapes(Type('S',(u,)),Span()))
        self.assertEqual([d.message for d in c.result.diagnostics],
            ['instantiated payload [Buffer<u64>; 2] hides resources in an unsupported container'])

    def test_selected_identity_failures_do_not_fall_back_but_profile_limits_do(self):
        from hepta.checker import _contains_capability as selected
        from hepta.borrowed_storage import contains_storage as storage_selected
        u=Type('u64')
        with patch.dict('os.environ',{'HEPTA_HIA_TYPE_GRAPH_MANIFEST':str(self.manifest)}):
            with patch('hepta.checker._contains_capability_reference',side_effect=AssertionError('foreign graph')):
                self.assertFalse(selected(u,{'Buffer'},{},{}))
            changed=self.folder/'changed-source.hiaasm';changed.write_bytes(SOURCE.read_bytes()+b'\n')
            with patch('hepta.hia_type_graph_native.SOURCE',changed):
                with self.assertRaisesRegex(ValueError,'source identity mismatch'):selected(u,{'Buffer'},{},{})
                with self.assertRaisesRegex(ValueError,'source identity mismatch'):storage_selected(u,{})
        with patch.dict('os.environ',{'HEPTA_HIA_TYPE_GRAPH_MANIFEST':'missing-manifest'}):
            with self.assertRaises((OSError,ValueError)):selected(u,{'Buffer'},{},{})
            self.assertFalse(selected(u,{'Buffer'},{}, {},frozenset('seen'+str(i) for i in range(8193))))
