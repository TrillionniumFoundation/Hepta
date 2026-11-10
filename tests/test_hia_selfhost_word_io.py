"""Actual compiler word helpers retain byte order and partial-write trap order."""
import ast
import ctypes
from hashlib import sha256
from pathlib import Path
import signal
import tempfile
import unittest
from tools.generate_hia_selfhost import (source_program, Builder, compact_authoring_cfg,
    total_scalar_functions)
from hepta.hia_agent_assembly import assemble_program, render_assembly

ROOT = Path(__file__).resolve().parents[1]
VALUE = 0x0102030405060789


def helper_source():
    source = source_program()
    nodes = ast.parse(source).body
    parts = [ast.get_source_segment(source, n) for n in nodes if n.name in ('put', 'get')]
    assert len(parts) == 2
    return ('def entry(s:readbuf, o:mutbuf, w:mutbuf) -> u32:\n'
        '    if byte(s, 0) == 0:\n        value = get(w, byte(s, 1))\n        put(o, 0, value)\n'
        f'    else:\n        put(o, byte(s, 1), {VALUE})\n    return 0\n\n' + '\n\n'.join(parts))


def document():
    nodes = ast.parse(helper_source()).body
    names = {n.name:'f'+str(i) for i,n in enumerate(nodes)}
    sigs = {n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    functions = []
    for n in nodes:
        b = Builder(n,names,sigs,total_scalar_functions(nodes)); b.statements(n.body)
        functions.append({'name':names[n.name], 'params':[b.param(p) for p in b.params],
            'returns':[b.returns], 'effects':['read','write','trap'], 'entry':'b0','blocks':b.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'word_io','functions':functions})


def reference(command, capacity, workspace):
    from hepta.hia_program_runtime import _Machine, _Owner, _View, HIAProgramTrap
    checked = assemble_program(render_assembly(document()))
    machine = _Machine(checked,1000000,16<<20,None,256)
    roots = [_Owner(-1,bytearray(command)), _Owner(-2,bytearray(b'\xa5'*capacity)),
             _Owner(-3,bytearray(workspace))]
    try:
        values = machine.invoke(checked.as_dict()['functions'][0],
            [_View(roots[0],False), _View(roots[1],True), _View(roots[2],True)])
    except HIAProgramTrap as error:
        return 'bounds',bytes(roots[1].data),bytes(roots[2].data)
    assert values == [0], values
    return 'returned',bytes(roots[1].data),bytes(roots[2].data)


class WordIOSourceTests(unittest.TestCase):
    def test_actual_helpers_match_integer_byte_formula_and_ordered_bounds(self):
        workspace = bytes(range(24))
        for offset in (0,1,7,8,16,17,23):
            command=bytes([0,offset]); status,output,after=reference(command,32,workspace)
            self.assertEqual(after,workspace)
            self.assertEqual(status,'returned' if offset<=16 else 'bounds')
            self.assertEqual(output,(workspace[offset:offset+8]+b'\xa5'*24) if offset<=16 else b'\xa5'*32)
        for capacity in range(10):
            for offset in (0,1,7):
                status,output,after=reference(bytes([1,offset]),capacity,workspace)
                expected=bytearray(b'\xa5'*capacity)
                for i,value in enumerate(VALUE.to_bytes(8,'little')):
                    if offset+i>=capacity:break
                    expected[offset+i]=value
                self.assertEqual(status,'returned' if offset+8<=capacity else 'bounds')
                self.assertEqual(output,bytes(expected)); self.assertEqual(after,workspace)


class WordIONativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert reference(b'\x01\x00',7,bytes(range(24)))[0]=='bounds'
        from tools.qualify_hia_selfhost import build_seed, compile_stage
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        cls.temporary=tempfile.TemporaryDirectory(prefix='hia-word-io-')
        cls.folder=Path(cls.temporary.name)
        seed,_=build_seed(cls.folder)
        source=(ROOT/'examples/hia_bootstrap/selfhost.hiaasm').read_bytes()
        first,_=compile_stage(cls.folder,'B1',seed,source,image_format='seed-shared')
        second,_=compile_stage(cls.folder,'B2',first,source)
        assert first.read_bytes()==second.read_bytes()
        cls.image,_=compile_stage(cls.folder,'word-io',second,render_assembly(document()).encode())
        cls.code=NativeHiaJsonImage(cls.image.read_bytes(),sha256(cls.image.read_bytes()).hexdigest())

    @classmethod
    def tearDownClass(cls):cls.temporary.cleanup()

    def test_actual_native_unaligned_reads_and_every_word_value_bit(self):
        for bit in range(64):
            value=1<<bit
            for offset in (0,1,7,8,16):
                workspace=bytearray(b'\x5a'*32);workspace[offset:offset+8]=value.to_bytes(8,'little')
                source=ctypes.create_string_buffer(bytes([0,offset]))
                out=ctypes.create_string_buffer(b'\xa5'*40,40)
                state=ctypes.create_string_buffer(bytes(workspace),32)
                self.assertEqual(self.code._entry(source,2,out,32,state,24),0)
                self.assertEqual(out.raw,value.to_bytes(8,'little')+b'\xa5'*32)
                self.assertEqual(state.raw,bytes(workspace))

    def test_real_SIGILL_preserves_prior_byte_stores_and_no_read_side_write(self):
        from tools.qualify_hia_selfhost import invoke
        for capacity in range(8):
            result,output=invoke(self.folder,'write-short-'+str(capacity),self.image,b'\x01\x00',
                capacity=capacity,workspace_size=24,observe_trap_writes=True)
            self.assertEqual(result['returncode'],-signal.SIGILL)
            self.assertEqual(output,VALUE.to_bytes(8,'little')[:capacity])
            self.assertTrue(result['shared_output_observation']['available'])
        result,output=invoke(self.folder,'read-short',self.image,b'\x00\x01',
            capacity=16,workspace_size=8,observe_trap_writes=True)
        self.assertEqual(result['returncode'],-signal.SIGILL)
        self.assertEqual(output,b'\xa5'*16)
