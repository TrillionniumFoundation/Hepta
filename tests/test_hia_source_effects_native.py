"""Independent VM, real bootstrap successors and actual checker-phase callers."""
from __future__ import annotations
import copy
import ctypes
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import json
from pathlib import Path
import random
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from hepta.ast import Span
from hepta.checker import _Checker
from hepta.parser import parse
from hepta.hia_source_effects_native import (SOURCE, SCHEMA, MAGIC,
    NativeSourceEffects, packet, materialize)
from tools.generate_hia_source_effects import document
ROOT=Path(__file__).resolve().parents[1]


def graph(local,declared=None,calls=None,resources=None,workers=()):
    c=_Checker(parse(''));declared=declared or {};resources=resources or {}
    c.local_effects={name:set(value) for name,value in local.items()}
    c.functions={name:SimpleNamespace(effects=set(declared.get(name,())),
        resources=dict.fromkeys(resources.get(name,()),0),span=Span(i,i+1,1,i+1,'effects.hepta'))
        for i,name in enumerate(local)}
    c.calls={name:set((calls or {}).get(name,())) for name in local}
    c.worker_sites=[(name,Span(100+i,101+i,2,i+1,'effects.hepta')) for i,name in enumerate(workers)]
    return c


def result(c):return c.result.effects,[d.to_dict() for d in c.result.diagnostics]


def vm_reference():
    from tests.test_hia_json_decode_native import vm_arena
    c=graph({'a':set(),'b':{'alloc'}},calls={'a':{'b'}},resources={'a':['heap_allocations']})
    p=packet(c);size,raw=vm_arena(p.wire,source_path=SOURCE,sizes=(p.capacity,p.workspace))
    # Literal bit/result decisions: both functions infer alloc; missing(a),
    # resource(a,heap), missing(b), in precisely the existing diagnostic order.
    expected=struct.pack('<4Q',MAGIC+1,2,3,0)+struct.pack('<2Q',1,1)
    expected+=struct.pack('<9Q',2,0,1,3,0,1,2,1,1)
    assert size==len(expected) and raw==expected,(size,raw,expected)
    materialize(raw,p,c)
    assert [d.code for d in c.result.diagnostics]==['E_EFFECT','E_RESOURCE','E_EFFECT']


class SourceEffectsSourceTests(unittest.TestCase):
    def test_generated_source_and_independent_VM_before_any_seed(self):
        from hepta.hia_agent_assembly import render_assembly
        self.assertEqual(SOURCE.read_text(),render_assembly(document()))
        vm_reference()


class SourceEffectsNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        vm_reference()
        from tools.qualify_hia_selfhost import build_seed,compile_stage
        cls.temporary=tempfile.TemporaryDirectory(prefix='hia-source-effects-')
        cls.folder=Path(cls.temporary.name)
        seed,_=build_seed(cls.folder)
        compiler=(ROOT/'examples/hia_bootstrap/selfhost.hiaasm').read_bytes()
        b1,_=compile_stage(cls.folder,'B1',seed,compiler,image_format='seed-shared')
        b2,_=compile_stage(cls.folder,'B2',b1,compiler)
        assert b1.read_bytes()==b2.read_bytes()
        image,cls.receipt=compile_stage(cls.folder,'source-effects',b2,SOURCE.read_bytes())
        raw=image.read_bytes();cls.native=NativeSourceEffects(raw,sha256(raw).hexdigest())
        cls.manifest=cls.folder/'manifest.json'
        cls.manifest.write_text(json.dumps({'schema':SCHEMA,'source_sha256':sha256(SOURCE.read_bytes()).hexdigest(),
            'image_path':image.name,'image_sha256':sha256(raw).hexdigest(),'compiler_sha256':sha256(b2.read_bytes()).hexdigest()}))

    @classmethod
    def tearDownClass(cls):cls.temporary.cleanup()

    def compare(self,c):
        expected=copy.deepcopy(c);expected._finish_effects_reference()
        self.native.finish(c)
        self.assertEqual(result(c),result(expected))

    def test_cycles_declared_bounds_unknowns_workers_resource_order_and_empty(self):
        self.compare(graph({}))
        self.compare(graph({'a':set(),'b':{'write'}},declared={'a':{'ffi','novel'},'b':{'alloc','unknown'}},
            calls={'a':{'b'},'b':{'a'}},resources={'a':['may_spawn','heap_allocations','may_block'],
            'b':['heap_allocations']},workers=['b','a','b']))
        self.compare(graph({'z':{'unknown','unsafe','block','spawn','alloc'},'a':set()},
            declared={'z':{'ffi'}},calls={'a':{'z'}},workers=['a','z'],
            resources={'z':['may_spawn','may_block','heap_allocations'],'a':['may_block']}))
        # Unknown declared bounds do not propagate, unknown local effects do.
        c=graph({'a':set(),'b':{'local_unknown'}},declared={'b':{'declaration_only'}},calls={'a':{'b'}})
        self.compare(c);self.assertEqual(c.result.effects['a'],{'local_unknown'})
        self.assertEqual(self.receipt['forbidden_compiler_modules_loaded'],[])

    def test_four_hundred_random_graphs_compared_to_original_phase(self):
        rng=random.Random(0xefec72026)
        alphabet=['alloc','block','spawn','panic','io','ffi','unsafe','write','novel','é😀']
        clauses=['heap_allocations','may_block','may_spawn','other']
        for _ in range(400):
            names=['f'+str(i) for i in range(rng.randrange(1,25))]
            pick=lambda values:{s for s in values if rng.randrange(6)==0}
            c=graph({name:pick(alphabet) for name in names},
                declared={name:pick(alphabet) for name in names},calls={name:pick(names) for name in names},
                resources={name:pick(clauses) for name in names},workers=rng.choices(names,k=rng.randrange(8)))
            self.compare(c)

    def test_profile_boundaries_all_bits_long_chain_and_concurrency(self):
        all_bits={'e'+str(i) for i in range(64)}
        self.compare(graph({'x':all_bits}))
        self.compare(graph({'f'+str(i):({'ffi'} if i==127 else set()) for i in range(128)},
            calls={'f'+str(i):{'f'+str(i+1)} for i in range(127)},workers=['f0']))
        self.compare(graph({'f'+str(i):set() for i in range(2048)}))
        c=graph({'x':{'ffi'}},workers=['x']*4096)
        self.compare(c)
        graphs=[graph({'a':set(),'b':{s}},calls={'a':{'b'}},workers=['a']) for s in all_bits]
        with ThreadPoolExecutor(max_workers=8) as pool:list(pool.map(self.compare,graphs))
        with self.assertRaises(ValueError):packet(graph({'x':all_bits|{'extra'}}))
        with self.assertRaises(ValueError):packet(graph({'x':set()},workers=['x']*4097))

    def test_malformed_input_and_buffer_refusals_preserve_output_and_guards(self):
        c=graph({'x':{'alloc'}},resources={'x':['heap_allocations']});p=packet(c)
        broken=[]
        for offset,value in ((0,0),(8,2049),(16,65),(24,16385),(32,8193),(40,4097),
                (48,8257),(56,113),(64,0),(72,0),(80,0),(88,0),(96,0),(104,0),
                (112,2),(128,1),(144,2)):
            wire=bytearray(p.wire);struct.pack_into('<Q',wire,offset,value);broken.append(bytes(wire))
        for wire,capacity,work,wanted in [(v,p.capacity,p.workspace,0xfffffffd) for v in broken]+[
                (p.wire[:111],p.capacity,p.workspace,0xfffffffd),
                (p.wire,p.capacity,p.workspace-1,0xfffffffd),
                (p.wire,1,p.workspace,0xfffffffe)]:
            s=ctypes.create_string_buffer(wire,len(wire));o=ctypes.create_string_buffer(b'\xa5'*(capacity+8),capacity+8)
            w=ctypes.create_string_buffer(b'\x5a'*(work+8),work+8)
            self.assertEqual(self.native._entry(s,len(wire),o,capacity,w,work),wanted,(len(wire),capacity,work))
            self.assertEqual(o.raw,b'\xa5'*(capacity+8));self.assertEqual(w.raw[work:],b'\x5a'*8)
            self.assertEqual(s.raw,wire)

    def test_complete_declared_graph_symbol_edge_and_byte_boundaries(self):
        names=['f'+str(i) for i in range(2048)]
        c=graph({name:({'e'+str(j) for j in range(64)} if i==0 else set())
                 for i,name in enumerate(names)},
            resources={name:['r'+str(i*4+j) for j in range(4)] for i,name in enumerate(names)})
        p=packet(c)
        self.assertEqual(struct.unpack_from('<Q',p.wire,32)[0],8192)
        self.assertEqual(struct.unpack_from('<Q',p.wire,48)[0],8256)
        self.compare(c)
        names=names[:128]
        c=graph(dict.fromkeys(names,set()),calls={name:set(names) for name in names})
        self.assertEqual(struct.unpack_from('<Q',packet(c).wire,24)[0],16384)
        self.compare(c)
        with self.assertRaises(ValueError):
            packet(graph(dict.fromkeys(names+['extra'],set()),
                calls={name:set(names+['extra']) for name in names}))
        symbol='x'*((1<<20)-112-48-16)
        c=graph({'one':{symbol}})
        self.assertEqual(len(packet(c).wire),1<<20)
        self.compare(c)
        with self.assertRaises(ValueError):packet(graph({'one':{symbol+'x'}}))
        with self.assertRaises(ValueError):packet(graph({'f'+str(i):set() for i in range(2049)}))

    def test_real_source_checkers_without_foreign_final_phase(self):
        from hepta.checker import check
        paths=sorted((ROOT/'tests').rglob('*.hepta'))+sorted((ROOT/'examples').rglob('*.hepta'))
        programs=[]
        from hepta.ast import HeptaError
        for path in paths:
            try:programs.append(parse(path.read_text(),str(path)))
            except HeptaError:continue
        self.assertTrue(programs)
        self.assertTrue(paths)
        type(self).fixture_inventory={'paths':len(paths),'parsed':len(programs),
            'syntax_error_inputs':len(paths)-len(programs)}
        with patch.dict('os.environ',{'HEPTA_HIA_SOURCE_EFFECTS_MANIFEST':''}):
            expected=[check(p) for p in programs]
        with patch.dict('os.environ',{'HEPTA_HIA_SOURCE_EFFECTS_MANIFEST':str(self.manifest)}):
            with patch.object(_Checker,'_finish_effects_reference',side_effect=AssertionError('foreign effect inference')):
                actual=[check(p) for p in programs]
        self.assertEqual(actual,expected)

    def test_selected_broken_image_refuses_and_outside_profile_keeps_reference(self):
        c=graph({'a':{'alloc'}})
        with patch.dict('os.environ',{'HEPTA_HIA_SOURCE_EFFECTS_MANIFEST':str(self.manifest)}):
            with patch.object(_Checker,'_finish_effects_reference',side_effect=AssertionError('foreign phase')):
                c.finish_effects()
            changed=self.folder/'changed-source.hiaasm';changed.write_bytes(SOURCE.read_bytes()+b'\n')
            with patch('hepta.hia_source_effects_native.SOURCE',changed):
                with self.assertRaisesRegex(ValueError,'source identity mismatch'):c.finish_effects()
        c=graph({'x':{'e'+str(i) for i in range(65)}})
        with patch.dict('os.environ',{'HEPTA_HIA_SOURCE_EFFECTS_MANIFEST':'missing-manifest'}):
            c.finish_effects()
        self.assertEqual(len(c.result.effects['x']),65)
