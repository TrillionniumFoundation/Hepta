"""Opt-in binary integer and opaque foreign-object graph transport controls."""
from __future__ import annotations
import json
import struct
import sys
import unittest
from unittest.mock import patch

from hepta.hia_instruction_policy_native import transport
from hepta.hia_native_value_graph import (
    NativeObjectPool, decode_bound_native_graph, decode_native_graph)


def node(kind,payload):
    return struct.pack('<2Q',kind,len(payload))+payload


def integer(value):
    count=(abs(value).bit_length()+7)//8
    return node(12,bytes([int(value<0)])+abs(value).to_bytes(count,'little'))


def array(*children):
    return node(5,struct.pack('<Q',len(children))+b''.join(children))


class NativeBinaryGraphTests(unittest.TestCase):
    def test_explicit_object_release_preserves_other_aliases_and_rejects_stale_ids(self):
        from hepta.hia_native_value_graph import NativeObjectPool
        events=[]
        class Held:
            def __del__(self):events.append('released')
        pool=NativeObjectPool()
        value=Held()
        first=pool.add(value);second=pool.add(value)
        del value
        pool.release(first)
        self.assertEqual(events,[])
        self.assertIsNotNone(pool.get(second))
        with self.assertRaisesRegex(ValueError,'released'):pool.get(first)
        with self.assertRaisesRegex(ValueError,'released'):pool.release(first)
        pool.release(second)
        self.assertEqual(events,['released'])
        third=pool.add(None)
        self.assertGreater(third,second)
        self.assertIsNone(pool.get(third))
        with self.assertRaises(ValueError):pool.release(True)

    def test_defaults_preserve_existing_tag_domain(self):
        for raw in (integer(0),integer(1),integer(-1),node(13,struct.pack('<Q',0))):
            with self.assertRaises(ValueError):decode_native_graph(raw,transport(None))
        with self.assertRaises(ValueError):
            decode_native_graph(node(8,struct.pack('<Q',0)),integer(7))

    def test_arbitrary_binary_magnitudes_do_not_trigger_decimal_digit_policy(self):
        values=[0,1,-1,1<<32,-(1<<64),(1<<127)-1,-(1<<127),(1<<131071)+17]
        saved=sys.get_int_max_str_digits()
        try:
            sys.set_int_max_str_digits(640)
            result=decode_native_graph(array(*(integer(v) for v in values)),transport(None),binary_integers=True)
            self.assertEqual(result,values)
            with self.assertRaises(ValueError):json.dumps(result)
        finally:sys.set_int_max_str_digits(saved)

    def test_binary_magnitude_and_sign_canonicality_and_extents(self):
        for payload in (b'',b'\x01',b'\x02',b'\x00\x00',b'\x01\x00',b'\x00\x01\x00'):
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError):
                    decode_native_graph(node(12,payload),transport(None),binary_integers=True)
        for raw in (struct.pack('<2Q',12,100)+b'\0\1',node(13,b''),node(13,b'\0'*16)):
            with self.assertRaises(ValueError):
                decode_native_graph(raw,transport(None),binary_integers=True,objects=NativeObjectPool())

    def test_binary_source_references_retain_identity_and_new_structure_binding(self):
        original=integer((1<<1024)+17)
        wire=array(node(8,struct.pack('<Q',0)),node(8,struct.pack('<Q',0)))
        value,binding=decode_bound_native_graph(wire,original,binary_integers=True)
        self.assertIs(value[0],value[1])
        binding.validate(value)
        value[0]=int.from_bytes(((1<<1024)+17).to_bytes(129,'little'),'little')
        self.assertIsNot(value[0],value[1])
        with self.assertRaises(ValueError):binding.validate(value)

    def test_opaque_policy_is_not_eagerly_admitted_or_serialized(self):
        calls=[]
        class Key:
            def __hash__(self):
                calls.append('hash')
                return hash('limit')
            def __eq__(self,other):
                calls.append('equal')
                return other=='limit'
        policy={Key():1<<20000}
        calls.clear()
        pool=NativeObjectPool()
        identifier=pool.add(policy)
        wire=node(6,struct.pack('<Q',1)+transport('limits')+node(13,struct.pack('<Q',identifier)))
        value,binding=decode_bound_native_graph(wire,transport(None),objects=pool)
        self.assertEqual(calls,[])
        self.assertIs(value['limits'],policy)
        binding.validate(value)
        with self.assertRaises(TypeError):json.dumps(value)
        value['limits']={}
        with self.assertRaises(ValueError):binding.validate(value)

    def test_opaque_ids_and_pool_type_are_checked_without_foreign_equality(self):
        pool=NativeObjectPool()
        value=object();pool.add(value)
        self.assertIs(decode_native_graph(node(13,struct.pack('<Q',0)),transport(None),objects=pool),value)
        for index in (1,(1<<64)-1):
            with self.assertRaises(ValueError):
                decode_native_graph(node(13,struct.pack('<Q',index)),transport(None),objects=pool)
        calls=[]
        class Meta(type):
            def __eq__(cls,other):calls.append('type comparison');return True
        class Fake(metaclass=Meta):pass
        with self.assertRaises(ValueError):
            decode_native_graph(transport(None),transport(None),objects=Fake())
        self.assertEqual(calls,[])
        pool.clear()
        with self.assertRaises(ValueError):pool.get(0)

    def test_extent_mode_has_no_fixed_node_or_expansion_quota(self):
        source=transport(['a','b','c'])
        wire=node(9,struct.pack('<3Q',2,0,0))
        with patch('hepta.hia_native_value_graph.MAX_NODES',2),patch(
                'hepta.hia_native_value_graph.MAX_EXPANDED_ELEMENTS',2):
            with self.assertRaises(ValueError):decode_native_graph(wire,source)
            value,binding=decode_bound_native_graph(wire,source,extent_bounds=True)
            self.assertEqual(value,['a','b','c','a','b','c'])
            self.assertIs(value[0],value[3])
            binding.validate(value)
        self.assertEqual(decode_native_graph(array(*(integer(n) for n in range(300))),transport(None),
                                            binary_integers=True,extent_bounds=True),list(range(300)))

    def test_extent_mode_keeps_parent_counts_and_depth_checks(self):
        for raw in (node(5,struct.pack('<Q',1<<63)),node(6,struct.pack('<Q',1<<63)),
                    node(5,struct.pack('<Q',2)+transport(None))):
            with self.assertRaises(ValueError):decode_native_graph(raw,transport(None),extent_bounds=True)
        raw=transport(None)
        for _ in range(129):raw=array(raw)
        with self.assertRaises(ValueError):decode_native_graph(raw,transport(None),extent_bounds=True)

    def test_hia_binary_writers_execute_in_independent_vm(self):
        import ast
        from hepta.hia_program import verify_core
        from hepta.hia_program_runtime import _Machine,_Owner,_View
        from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
        from tools.hia_program_execution_scalars import ScalarBuilder
        from tools.generate_hia_instruction_policy import SOURCE
        from tools.hia_native_bigints import BODY as INTEGERS
        from tools.hia_native_value_graph import BODY,BINARY_BODY
        own=ast.parse('''
def entry(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    put(w, 4120, 0)
    put(w, 4128, 0)
    array = graph_begin(o, w, 5, 3)
    big_init(w, 256, 5)
    graph_binary_integer(o, w, 256)
    big_set_u64(w, 256, 1, 18446744073709551615)
    big_shl(w, 256, 256, 33)
    graph_binary_integer(o, w, 256)
    graph_object(o, w, 0)
    graph_end(o, w, array)
    return get(w, 4120)
def append_byte(o:mutbuf,w:mutbuf,value:u64) -> u64:
    at = get(w, 4120)
    if at >= length(o):
        put(w, 4128, 1)
        return 0
    store(o, at, value)
    put(w, 4120, at + 1)
    return 1
''')
        own.body += [n for n in ast.parse(SOURCE.replace('    DISPATCH','    pass')).body
                     if isinstance(n,ast.FunctionDef) and n.name in {'get','put'}]
        own.body += ast.parse(INTEGERS+BINARY_BODY).body
        own.body += [n for n in ast.parse(BODY).body if n.name in {'graph_begin','graph_end','graph_word'}]
        class Constants(ast.NodeTransformer):
            def visit_Name(self,node):
                return ast.Constant({'S':4096,'O_BYTES':4096}[node.id]) if node.id in {'S','O_BYTES'} else node
        nodes=ast.fix_missing_locations(Constants().visit(own)).body
        names={n.name:'f'+str(i) for i,n in enumerate(nodes)}
        signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
        total=total_scalar_functions(nodes);functions=[]
        for n in nodes:
            builder=ScalarBuilder(n,names,signatures,total);builder.statements(n.body)
            functions.append({'name':names[n.name],'params':[builder.param(v) for v in builder.params],
                'returns':[builder.returns],'effects':['read','write','trap'],'entry':'b0','blocks':builder.blocks})
        checked=verify_core(compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'binary_graph','functions':functions}))
        roots=[_Owner(-1,bytearray()),_Owner(-2,bytearray(4096)),_Owner(-3,bytearray(8192))]
        machine=_Machine(checked,1_000_000,0,None,256)
        count=machine.invoke(machine.functions['f0'],[_View(v,i!=0) for i,v in enumerate(roots)])[0]
        expected=array(integer(0),integer(-(((1<<64)-1)<<33)),node(13,struct.pack('<Q',0)))
        self.assertEqual(bytes(roots[1].data[:count]),expected)
        self.assertEqual(struct.unpack_from('<Q',roots[2].data,4128),(0,))
        pool=NativeObjectPool();held=object();pool.add(held)
        result=decode_native_graph(expected,transport(None),binary_integers=True,objects=pool)
        self.assertEqual(result[:2],[0,-(((1<<64)-1)<<33)])
        self.assertIs(result[2],held)


if __name__=='__main__':unittest.main()
