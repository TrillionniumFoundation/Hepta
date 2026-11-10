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
from hepta.ast import Type, Struct, Enum, EnumVariant, Param, HeptaError
from hepta.checker import _contains_capability_reference as _contains_capability
from hepta.borrowed_storage import _contains_storage_reference as contains_storage
from hepta.hia_type_graph_native import (SOURCE, SCHEMA, MAGIC, WORKSPACE,
    NativeTypeGraph, GraphProfileLimit, packet, materialize)
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


class TypeGraphSourceTests(unittest.TestCase):
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

    def test_actual_source_callers_without_either_foreign_graph_query(self):
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
                    patch('hepta.borrowed_storage._contains_storage_reference',side_effect=AssertionError('foreign storage graph')):
                actual=[check(p) for p in programs]
        self.assertEqual(actual,expected)

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
