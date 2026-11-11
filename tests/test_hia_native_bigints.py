"""Independent mathematical and actual-machine controls for HIA integers.

The wrapper is a standalone test kernel. No hosted bigint implementation is
selected by production owners; their checked HIA sources include BODY itself.
"""
from __future__ import annotations
import ast
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import random
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_program import verify_core
from hepta.hia_program_runtime import _Machine, _Owner, _View
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from tools.hia_native_bigints import BODY
from tools.hia_program_execution_scalars import ScalarBuilder

ROOT = Path(__file__).resolve().parents[1]
DEVELOPMENT_COMPILER = 'HEPTA_HIA_BIGINT_DEVELOPMENT_COMPILER'
COLD_REPORT = 'HEPTA_HIA_STATIC_BUDGET_COLD_REPORT'
EVIDENCE = 'HEPTA_HIA_BIGINT_EVIDENCE'
ABI = 0xfffffff1
MASK = (1 << 64) - 1

WRAPPER = r'''
def bigint_probe(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if big_probe_prepare(s, o, w) == 0:
        return 4294967281
    out = get(w, 16)
    span = 24 + get(w, out + 16) * 8
    index = 0
    while index < span:
        store(o, 96 + index, byte(w, out + index))
        index = index + 1
    op = read(s, 0)
    status = 0
    if op == 1:
        status = big_add(w, out, get(w, 0), get(w, 8))
    elif op == 2:
        status = big_sub(w, out, get(w, 0), get(w, 8))
    elif op == 3:
        status = big_mul(w, out, get(w, 0), get(w, 8))
    elif op == 4:
        status = big_shl(w, out, get(w, 0), read(s, 24))
    elif op == 5:
        status = 1
    elif op == 6 or op == 9:
        status = big_copy(w, out, get(w, 0))
    elif op == 7:
        status = big_set_u64(w, out, read(s, 32), read(s, 24))
    elif op == 10:
        put(w, get(w, 0), 2)
        status = big_valid(w, get(w, 0))
    put(o, 0, status)
    put(o, 8, get(w, 24))
    put(o, 16, big_bit_length(w, out))
    put(o, 24, get(w, out))
    put(o, 32, get(w, out + 8))
    put(o, 40, big_byte_length(w, out))
    put(o, 48, out)
    put(o, 56, get(w, out + 16))
    put(o, 64, big_valid(w, out))
    put(o, 80, span)
    extent = get(w, out + 16) * 4
    if op == 9:
        extent = read(s, 24)
    put(o, 72, big_export_le(w, out, o, 96 + span, extent))
    return 1

def big_probe_prepare(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if length(s) < 64 or length(w) < length(s) + 256:
        return 0
    a_count = read(s, 40)
    b_count = read(s, 56)
    if a_count > length(s) - 64 or b_count != length(s) - 64 - a_count:
        return 0
    index = 0
    while index < length(s):
        store(w, index, byte(s, index))
        index = index + 1
    a = (length(s) + 263) & 18446744073709551608
    if big_init(w, a, a_count // 4 + choose(a_count % 4 != 0, 1, 0)) == 0:
        return 0
    b = a + 24 + get(w, a + 16) * 8
    if big_init(w, b, b_count // 4 + choose(b_count % 4 != 0, 1, 0)) == 0:
        return 0
    out = b + 24 + get(w, b + 16) * 8
    if big_init(w, out, read(s, 16)) == 0:
        return 0
    big_set_u64(w, out, 0, 11)
    if big_import_le(w, a, 64, a_count, read(s, 32)) == 0:
        return 0
    if big_import_le(w, b, 64 + a_count, b_count, read(s, 48)) == 0:
        return 0
    if read(s, 8) == 1:
        out = a
    elif read(s, 8) == 2:
        out = b
    if length(o) < 120 + get(w, out + 16) * 12:
        return 0
    put(w, 0, a)
    put(w, 8, b)
    put(w, 16, out)
    put(w, 24, big_cmp(w, a, b))
    return 1

def read(s:readbuf, at:u64) -> u64:
    index = 0
    value = 0
    while index < 8:
        value = value | (byte(s, at + index) << (index * 8))
        index = index + 1
    return value

def get(w:mutbuf, at:u64) -> u64:
    index = 0
    value = 0
    while index < 8:
        value = value | (byte(w, at + index) << (index * 8))
        index = index + 1
    return value

def put(w:mutbuf, at:u64, value:u64) -> u64:
    index = 0
    while index < 8:
        store(w, at + index, (value >> (index * 8)) & 255)
        index = index + 1
    return 0
'''


def document():
    nodes = ast.parse(WRAPPER + BODY).body
    names = {node.name:'f'+str(index) for index,node in enumerate(nodes)}
    signatures = {node.name:([arg.annotation.id for arg in node.args.args],node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = ScalarBuilder(node,names,signatures,total)
        builder.statements(node.body)
        functions.append({'name':names[node.name],'params':[builder.param(arg) for arg in builder.params],
            'returns':[builder.returns],'effects':['read','write','trap'],'entry':'b0','blocks':builder.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'bigint_probe','functions':functions})


def limbs(value):
    return (abs(value).bit_length() + 31) // 32


def magnitude(value):
    return abs(value).to_bytes((abs(value).bit_length() + 7) // 8, 'little')


class NativeBigIntSourceTests(unittest.TestCase):
    def test_authoring_has_only_typed_native_functions_and_original_limits(self):
        from tools.hia_selfhost_limits import MAX_FUNCTIONS, MAX_BLOCKS, MAX_INSTRUCTIONS
        nodes = ast.parse(BODY).body
        self.assertTrue(all(isinstance(node,ast.FunctionDef) and node.name.startswith('big_') for node in nodes))
        value = document()
        self.assertTrue(verify_core(value).sha256)
        self.assertLessEqual(len(value['functions']),MAX_FUNCTIONS)
        self.assertLessEqual(sum(len(fn['blocks']) for fn in value['functions']),MAX_BLOCKS)
        self.assertLessEqual(sum(len(block['ops']) for fn in value['functions'] for block in fn['blocks']),MAX_INSTRUCTIONS)
        self.assertLessEqual(max(len(block['params']) for fn in value['functions'] for block in fn['blocks']),16)

    def test_cold_and_development_conflict_before_input_read(self):
        with patch.dict(os.environ,{COLD_REPORT:'/unread-cold',DEVELOPMENT_COMPILER:'/unread-development'}),patch.object(
                Path,'read_bytes',side_effect=AssertionError('read before fixture conflict')):
            with self.assertRaisesRegex(RuntimeError,'mutually exclusive'):
                NativeBigIntMachineTests.setUpClass()


class NativeBigIntMachineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cold,development = os.environ.get(COLD_REPORT),os.environ.get(DEVELOPMENT_COMPILER)
        if cold and development:
            raise RuntimeError('cold and retained development bigint fixtures are mutually exclusive')
        if not cold and not development:
            raise unittest.SkipTest('explicit cold report or retained development compiler required')
        from tools.qualify_hia_selfhost import compile_stage
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        names = ('tools/hia_native_bigints.py','tests/test_hia_native_bigints.py',
                 'tools/hia_program_execution_scalars.py','tools/generate_hia_selfhost.py',
                 'hepta/hia_program_runtime.py','tools/qualify_hia_selfhost.py')
        cls.inputs={name:(ROOT/name).read_bytes() for name in names}
        cls.cold_bytes=None
        if cold:
            from tools.build_hia_json_preflight import admit_cold_build
            cls.cold_bytes=Path(cold).read_bytes()
            value=json.loads(cls.cold_bytes)
            nested=json.loads(Path(value['nested_report']).read_bytes())
            cls.compiler=Path(nested['generations'][-1]['produced_image'])
            cls.compiler_bytes=cls.compiler.read_bytes()
            cls.cold_sources=admit_cold_build(cls.compiler_bytes,cls.cold_bytes)
            cls.scope='CURRENT_SOURCE_COLD_COMPILER_STANDALONE_ARITHMETIC_CONTROL'
        else:
            cls.compiler=Path(development)
            cls.compiler_bytes=cls.compiler.read_bytes()
            cls.scope='RETAINED_COMPILER_DEVELOPMENT_STANDALONE_ARITHMETIC_CONTROL'
        cls.folder=Path(os.environ.get(EVIDENCE) or tempfile.mkdtemp(prefix='hia-bigint-'))
        cls.folder.mkdir(parents=True,exist_ok=True)
        cls.document=document()
        cls.checked=verify_core(cls.document)
        cls.source=render_assembly(cls.document).encode()
        cls.image,receipt=compile_stage(cls.folder,'bigint-probe',cls.compiler,cls.source)
        cls.image_bytes=cls.image.read_bytes()
        cls.native=NativeHiaJsonImage(cls.image_bytes,sha256(cls.image_bytes).hexdigest())
        cls.native_entries=cls.vm_entries=cls.math_controls=0
        for name,data in cls.inputs.items():
            path=cls.folder/'frozen-inputs'/name
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(data)
        (cls.folder/'source-before.json').write_text(json.dumps(
            {name:sha256(data).hexdigest() for name,data in cls.inputs.items()},indent=2,sort_keys=True)+'\n')
        (cls.folder/'compile-receipt.json').write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n')

    @classmethod
    def tearDownClass(cls):
        stable=all((ROOT/name).read_bytes()==data for name,data in cls.inputs.items())
        build_stable=cls.image.read_bytes()==cls.image_bytes and cls.compiler.read_bytes()==cls.compiler_bytes
        if cls.cold_bytes is not None:
            from tools.build_hia_json_preflight import current_sources
            build_stable=build_stable and Path(os.environ[COLD_REPORT]).read_bytes()==cls.cold_bytes and current_sources()==cls.cold_sources
        (cls.folder/'observations.json').write_text(json.dumps({'scope':cls.scope,'source_unchanged':stable,
            'build_inputs_unchanged':build_stable,'native_entries':cls.native_entries,'independent_vm_entries':cls.vm_entries,
            'independent_math_controls':cls.math_controls,'source_sha256':sha256(cls.source).hexdigest(),
            'image_sha256':sha256(cls.image_bytes).hexdigest(),'compiler_sha256':sha256(cls.compiler_bytes).hexdigest()},indent=2,sort_keys=True)+'\n')
        if not stable or not build_stable:raise AssertionError('bigint fixture inputs changed')

    def invoke(self,op,a,b=0,*,shift=0,alias=0,capacity=None,vm=False,raw_a=None,sign_a=None):
        if capacity is None:capacity=max(2,limbs(a)+limbs(b)+2,(abs(a).bit_length()+shift+31)//32+1 if op==4 else 0)
        original = a if alias==1 else b if alias==2 else 11 if capacity else 0
        out_capacity = limbs(a) if alias==1 else limbs(b) if alias==2 else capacity
        am=magnitude(a) if raw_a is None else raw_a
        bm=magnitude(b)
        packet=struct.pack('<8Q',op,alias,capacity,shift,int(a<0) if sign_a is None else sign_a,len(am),int(b<0),len(bm))+am+bm
        workspace_size=((len(packet)+263)&~7)+72+(limbs(a)+limbs(b)+capacity)*8+64
        output_size=120+out_capacity*12+32
        guard=b'\xB7'*16
        source=ctypes.create_string_buffer(guard+packet+guard,len(packet)+32)
        workspace=ctypes.create_string_buffer(guard+b'\xA5'*workspace_size+guard,workspace_size+32)
        output=ctypes.create_string_buffer(guard+b'\xC3'*output_size+guard,output_size+32)
        before=bytes(workspace)[16:-16]
        output_before=bytes(output)[16:-16]
        returned=self.native._entry(ctypes.byref(source,16),len(packet),ctypes.byref(output,16),output_size,
                                   ctypes.byref(workspace,16),workspace_size)
        type(self).native_entries+=1
        for value in (source,workspace,output):
            self.assertEqual(bytes(value)[:16],guard)
            self.assertEqual(bytes(value)[-16:],guard)
        self.assertEqual(bytes(source)[16:-16],packet)
        actual_output=bytes(output)[16:-16]
        actual_workspace=bytes(workspace)[16:-16]
        if vm:
            roots=[_Owner(-1,bytearray(packet)),_Owner(-2,bytearray(output_before)),_Owner(-3,bytearray(before))]
            machine=_Machine(self.checked,10_000_000,0,None,256)
            values=machine.invoke(machine.functions['f0'],[_View(root,index!=0) for index,root in enumerate(roots)])
            self.assertEqual(values,[returned])
            self.assertEqual(bytes(roots[0].data),packet)
            self.assertEqual(bytes(roots[1].data),actual_output)
            self.assertEqual(bytes(roots[2].data),actual_workspace)
            type(self).vm_entries+=1
        if raw_a is not None or sign_a is not None:
            return returned,actual_output,actual_workspace
        self.assertEqual(returned,1)
        status,comparison,bits,negative,count,size,at,cap,valid,exported,span=struct.unpack_from('<11Q',actual_output)
        self.assertEqual(comparison,0 if a==b else 1 if a<b else 2)
        self.assertEqual((cap,span,valid),(out_capacity,24+out_capacity*8,1))
        expected=original
        success=True
        if op in (1,2):
            candidate=a+b if op==1 else a-b
            success=limbs(candidate)<=out_capacity
            if success:expected=candidate
        elif op==3:
            success=not alias and (a==0 or b==0 or limbs(a)+limbs(b)<=out_capacity)
            if success:expected=a*b
        elif op==4:
            success=a==0 or abs(a).bit_length()+shift<=out_capacity*32
            if success:expected=a<<shift
        elif op in (6,9):
            success=limbs(a)<=out_capacity
            if success:expected=a
        elif op==7:
            candidate=-shift if a<0 else shift
            success=limbs(candidate)<=out_capacity
            if success:expected=candidate
        elif op==10:success=False
        self.assertEqual(status,int(success))
        self.assertEqual((bits,negative,count,size),(abs(expected).bit_length(),int(expected<0),limbs(expected),len(magnitude(expected))))
        extent=shift if op==9 else out_capacity*4
        export_expected=size<=extent and extent<=output_size-(96+span)
        self.assertEqual(exported,int(export_expected))
        if exported:
            raw=actual_output[96+span:96+span+size]
            result=int.from_bytes(raw,'little')*(-1 if negative else 1)
            self.assertEqual(result,expected)
        else:
            self.assertEqual(actual_output[96+span:],output_before[96+span:])
        if not success:
            self.assertEqual(actual_workspace[at:at+span],actual_output[96:96+span])
        type(self).math_controls+=1
        return expected

    def test_signed_add_subtract_comparison_and_aliases(self):
        values={0,-1,1}
        for width in (8,16,31,32,33,63,64,65,96,127,128,255):
            for delta in (-1,0,1):
                value=(1<<width)+delta
                values.update((value,-value))
        values=sorted(values)
        for index,a in enumerate(values):
            for b in (values[index],values[-index-1],0,1,-1):
                for op in (1,2,5):
                    for alias in (0,1,2):
                        self.invoke(op,a,b,alias=alias)

    def test_multiply_exact_machine_endpoints_and_arbitrary_precision(self):
        values=[0,1,-1,(1<<32)-1,-(1<<32),1<<63,-(1<<63),(1<<64)-1,-((1<<64)-1),
                (1<<127)-1,-(1<<127),(1<<255)+0x1122334455667788]
        for a in values:
            for b in values:self.invoke(3,a,b)
        rng=random.Random(10671)
        for width in (129,256,512,1024,2048,4096):
            for _ in range(3):
                self.invoke(3,rng.getrandbits(width)*rng.choice((-1,1)),rng.getrandbits(width)*rng.choice((-1,1)))

    def test_shift_carry_across_limbs_and_in_place(self):
        for a in (0,1,-1,(1<<32)-1,-((1<<32)-1),(1<<64)-1,-(1<<127)):
            for shift in (0,1,7,8,31,32,33,63,64,65,127,128,257):
                for alias in (0,1):self.invoke(4,a,shift=shift,alias=alias)
        self.invoke(4,0,shift=MASK,capacity=0)
        self.invoke(4,1,shift=MASK,capacity=1)

    def test_capacity_and_prohibited_alias_refusals_preserve_output(self):
        for op,a,b,capacity in ((1,(1<<32)-1,1,1),(2,0,1<<64,1),(2,1<<64,1<<64,0),
                               (3,(1<<32)-1,(1<<32)-1,1),(3,0,1<<128,0),(6,1<<96,0,2)):
            self.invoke(op,a,b,capacity=capacity)
        for alias in (1,2):self.invoke(3,37,-19,alias=alias)
        self.invoke(4,1<<31,shift=1,capacity=1)
        self.invoke(9,(1<<65)+1,shift=8,capacity=3)
        self.invoke(9,0,shift=MASK,capacity=1)

    def test_binary_import_export_canonical_zero_and_no_decimal_policy(self):
        saved=sys.get_int_max_str_digits()
        try:
            sys.set_int_max_str_digits(640)
            huge=(1<<131071)+(1<<65536)+31
            self.invoke(1,huge,-(1<<65536))
            self.invoke(4,-huge,shift=33)
            self.invoke(6,huge)
        finally:sys.set_int_max_str_digits(saved)
        for raw,sign in ((b'',1),(b'\0',0),(b'\x01\0',0),(b'\x01',2)):
            result,_,_=self.invoke(6,1,raw_a=raw,sign_a=sign,capacity=2)
            self.assertEqual(result,ABI)
        self.invoke(10,37,19)
        for value in (0,1,(1<<32)-1,1<<32,(1<<64)-1):
            for sign in (-1,1):self.invoke(7,sign,shift=value)

    def test_independent_reference_vm_complete_storage_and_guards(self):
        for op,a,b,options in [
            (1,(1<<32)-1,1,{}),(1,-(1<<64),17,{'alias':1}),
            (2,1<<96,(1<<96)-1,{'capacity':1}),(2,-17,19,{'alias':2}),
            (3,(1<<64)-1,-(1<<63),{}),(3,37,11,{'alias':1}),
            (4,-((1<<33)+1),0,{'shift':31}),(4,(1<<32)-1,0,{'shift':1,'alias':1}),
            (6,-(1<<65),0,{}),(9,(1<<65)+1,0,{'shift':8,'capacity':3}),
        ]:
            self.invoke(op,a,b,vm=True,**options)


if __name__=='__main__':
    unittest.main()
