"""Actual Core editing callers, independent VM and native refusal canaries."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
import ctypes
from hashlib import sha256
import io
import json
from pathlib import Path
import random
import re
import subprocess
import struct
import tempfile
import unittest
from unittest.mock import patch
from hepta.hia_agent_slice_native import (MAGIC, RESULT_MAGIC, NONE, SOURCE, SCHEMA,
    NativeAgentSlice, encode_function, native_edit_slice, installed_agent_slice)
ROOT = Path(__file__).resolve().parents[1]


def independent_cases():
    # Hand-authored graph and every result byte, not the transport or host slicer.
    first = struct.pack('<8Q', MAGIC, 2, 1, 2, 1, 3, 0, 0)
    first += struct.pack('<16Q', 0,0,0,1,1,NONE,0,1, 1,1,1,0,0,NONE,2,1)
    first += struct.pack('<5Q', 0,0,0,0,1)
    first += struct.pack('<4Q', 0,0,1,NONE)
    first += struct.pack('<4Q', 0,1,1,1)
    first += struct.pack('<3Q', 0,0,1)
    expected = struct.pack('<13Q', RESULT_MAGIC,2,1,2,0,0,1,0, 0,1, 1,3, 3)
    second = struct.pack('<8Q', MAGIC,3,3,3,2,3,0,0)
    second += struct.pack('<24Q', 0,0,0,1,2,0,0,1,
                         1,0,1,1,0,NONE,1,1, 2,0,2,1,0,NONE,2,1)
    second += struct.pack('<15Q', 0,0,0,0,1, 1,0,0,1,1, 2,0,0,2,1)
    second += struct.pack('<6Q', 0,0,1,1,2,2)
    second += struct.pack('<8Q', 0,1,1,0, 0,2,1,0)
    second += struct.pack('<3Q', 0,1,2)
    expected2 = struct.pack('<17Q', RESULT_MAGIC,3,3,3,0,0,3,0, 0,3,3, 1,0,0, 3,2,2)
    return [(first, expected), (second, expected2)]


def vm(wire, capacity):
    from tools.hia_selfhost_bulk import Body
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import execute_program
    body, owners, views = Body(0), [], []
    for size, initial in ((len(wire), wire), (capacity, bytes([90])*capacity), (4096, b'')):
        owner = body.value('buffer','buffer.new',[body.const('usize',size)])
        view = body.value('mutbuf','borrow.mut',[owner])
        for i, byte in enumerate(initial):
            if byte: body.effect('buffer.store',[view,body.const('usize',i),body.const('u8',byte)])
        owners.append(owner); views.append(view)
    body.effect('loan.end',[views[0]])
    views[0] = body.value('readbuf','borrow.read',[owners[0]])
    result = body.value('u32','call',views,{'function':'f0'})
    raw = [body.value('u8','buffer.load',[views[1],body.const('usize',i)]) for i in range(capacity)]
    for v in views: body.effect('loan.end',[v])
    for owner in owners: body.effect('owner.drop',[owner])
    wrapper = ('hia-asm.v1 hepta.hia.program.v8 agent_slice_reference\nfn observe() -> (u32,'
        + ','.join(['u8']*capacity)+') effects(alloc,read,write,trap) entry(b0)\nblock b0()\n'
        +body.text()+'  ret('+','.join([result,*raw])+')\nend\n'+SOURCE.read_text().split('\n',1)[1])
    actual = execute_program(assemble_program(wrapper),'observe',[],max_steps=3000000)
    assert actual['status'] == 'returned', actual
    assert actual['resources']['live_owners'] == actual['resources']['live_local_loans'] == 0
    result, *raw = actual['values']
    return result, bytes(raw)


def references():
    cases = independent_cases()
    for wire, expected in cases:
        assert vm(wire, len(expected)) == (len(expected), expected)
    assert vm(cases[0][0]+b'!',32) == (0xffffffff,bytes([90])*32)
    assert vm(cases[0][0],32) == (0xfffffffe,bytes([90])*32)
    return cases


class AgentSliceSourceTests(unittest.TestCase):
    def test_generated_source_and_independent_VM_before_native_seed(self):
        from hepta.hia_agent_assembly import render_assembly
        from tools.generate_hia_agent_slice import document
        self.assertEqual(SOURCE.read_text(),render_assembly(document()))
        self.assertEqual(len(references()),2)


class AgentSliceNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.references = references()  # Actual independent HIA before B0.
        from tools.qualify_hia_selfhost import build_seed,compile_stage
        cls.temporary = tempfile.TemporaryDirectory(prefix='hia-agent-slice-')
        cls.folder = Path(cls.temporary.name)
        seed,_ = build_seed(cls.folder)
        source = (ROOT/'examples/hia_bootstrap/selfhost.hiaasm').read_bytes()
        first,_ = compile_stage(cls.folder,'B1',seed,source,image_format='seed-shared')
        second,_ = compile_stage(cls.folder,'B2',first,source)
        assert first.read_bytes() == second.read_bytes()
        image,cls.compile_receipt = compile_stage(cls.folder,'agent-slice',second,SOURCE.read_bytes())
        cls.native = NativeAgentSlice(image.read_bytes(),sha256(image.read_bytes()).hexdigest())
        cls.manifest = cls.folder/'manifest.json'
        cls.manifest.write_text(json.dumps({'schema':SCHEMA,'source_sha256':sha256(SOURCE.read_bytes()).hexdigest(),
            'image_path':image.name,'image_sha256':sha256(image.read_bytes()).hexdigest(),
            'compiler_sha256':sha256(second.read_bytes()).hexdigest()}))

        from tools.generate_hia_native_filter import MAGIC as FILTER_MAGIC
        from tools.qualify_hia_selfhost import invoke
        packer,_=compile_stage(cls.folder,'filter-packer',second,
            (ROOT/'examples/hia_bootstrap/native_filter_packer.hiaasm').read_bytes())
        receipt,raw=invoke(cls.folder,'pack-filter',packer,
            struct.pack('<2Q',FILTER_MAGIC,image.stat().st_size)+image.read_bytes())
        assert 0<receipt['core_u32']<=len(raw)
        cls.executable=cls.folder/'hia-agent-slice'
        cls.executable.write_bytes(raw[:receipt['core_u32']]);cls.executable.chmod(0o700)

    @classmethod
    def tearDownClass(cls): cls.temporary.cleanup()

    def test_every_native_byte_matches_independent_before_seed_VM(self):
        for wire,expected in self.references: self.assertEqual(self.native.run(wire),expected)
        self.assertEqual(self.compile_receipt['forbidden_compiler_modules_loaded'],[])

    def test_selected_existing_edit_query_batch_CFG_control_and_snapshot_callers(self):
        names = ['tests.test_hia_edit_query','tests.test_hia_edit_transitive_context',
            'tests.test_hia_edit_cfg_context','tests.test_hia_edit_control_context',
            'tests.test_hia_edit_batch','tests.test_hia_edit_batch_identity',
            'tests.test_hia_edit_snapshot_race','tests.test_hia_agent_entry']
        suite = unittest.defaultTestLoader.loadTestsFromNames(names)
        stream = io.StringIO()
        with (patch.dict('os.environ',{'HEPTA_HIA_AGENT_SLICE_MANIFEST':str(self.manifest)}),
              patch('hepta.hia_edit_query._reference_edit_slice',side_effect=AssertionError('foreign SSA slicer')),
              patch('hepta.hia_edit_query._cfg_downstream_slice',side_effect=AssertionError('foreign CFG slicer'))):
            result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
        self.assertTrue(result.wasSuccessful(),stream.getvalue())
        self.assertEqual(len(result.skipped),0)
        self.assertGreater(result.testsRun,50)

    def test_random_verified_DAGs_preserve_entire_query(self):
        from hepta.hia_edit_query import prepare_edit
        from hepta.hia_program_tools import HIAEditRejected
        from tests.test_hia_program import b,c,f,i,m,ret,jump,branch
        rng = random.Random(7753)
        for case in range(160):
            n = rng.randrange(2,10)
            blocks=[]
            for bi in range(n):
                param='arg'+str(bi)
                ops=[c('k'+str(bi),'u32',rng.randrange(9)),
                     i('int.add.wrap',[param,'k'+str(bi)],[('v'+str(bi),'u32')]),
                     i('compare.lt',[param,'v'+str(bi)],[('cond'+str(bi),'bool')])]
                if bi+1==n: term=ret('v'+str(bi))
                elif rng.randrange(3):term=jump('b'+str(bi+1),'v'+str(bi))
                else:
                    dest=rng.randrange(bi+1,n)
                    term=branch('cond'+str(bi),('b'+str(bi+1),'v'+str(bi)),('b'+str(dest),param))
                blocks.append(b('b'+str(bi),[(param,'u32')],ops,term))
            # All blocks remain reachable via the fallthrough chain. Reorder
            # declarations to make FIFO, not declaration order, significant.
            rng.shuffle(blocks)
            document=m(f('work',[('arg0','u32')],['u32'],[],blocks))
            document['functions'][0]['entry']='b0'
            chosen=rng.randrange(n)
            selected='cond' if case%3==0 else 'v'
            kwargs=dict(function='work',block='b'+str(chosen),output=selected+str(chosen),fields=['op'])
            with patch.dict('os.environ',{'HEPTA_HIA_AGENT_SLICE_MANIFEST':''}): expected=prepare_edit(document,**kwargs)
            with (patch.dict('os.environ',{'HEPTA_HIA_AGENT_SLICE_MANIFEST':str(self.manifest)}),
                  patch('hepta.hia_edit_query._reference_edit_slice',side_effect=AssertionError('fallback'))):
                self.assertEqual(prepare_edit(document,**kwargs),expected,'random case '+str(case))

    def test_packet_field_refusals_no_partial_output_and_workspace_is_private(self):
        wire,expected=self.references[0]
        cases=[b'',wire+b'!',wire[:-1]]
        for at in (0,8,16,24,32,40,48,56,64,72,80,88,96,104,112,120,192,200,208,216,224,232,240):
            if at+8<=len(wire):
                changed=bytearray(wire);struct.pack_into('<Q',changed,at,NONE)
                if bytes(changed)!=wire: cases.append(bytes(changed))
        for raw in cases:
            source=ctypes.create_string_buffer(raw,max(1,len(raw)))
            output=ctypes.create_string_buffer(bytes([90])*512)
            state=ctypes.create_string_buffer(bytes([165])*4096)
            code=self.native._entry(source,len(raw),output,512,state,4096)
            self.assertEqual(code,0xffffffff)
            self.assertEqual(output.raw[:512],bytes([90])*512)
        source=ctypes.create_string_buffer(wire,len(wire))
        for capacity,scratch in ((len(expected)-1,4096),(512,len(expected)+15)):
            output=ctypes.create_string_buffer(bytes([90])*512)
            state=ctypes.create_string_buffer(bytes([165])*4096)
            code=self.native._entry(source,len(wire),output,capacity,state,scratch)
            self.assertEqual(code,0xfffffffe)
            self.assertEqual(output.raw[:512],bytes([90])*512)
        output=ctypes.create_string_buffer(bytes([90])*512)
        state=ctypes.create_string_buffer(bytes([165])*4096)
        self.assertEqual(self.native._entry(source,len(wire),output,512,state,4096),len(expected))
        self.assertEqual(output.raw[:len(expected)],expected)
        self.assertEqual(output.raw[len(expected):512],bytes([90])*(512-len(expected)))

    def test_exact_256_operation_and_64_block_budgets(self):
        from hepta.hia_edit_query import prepare_edit
        from hepta.hia_program_tools import HIAEditRejected
        from tests.test_hia_program import b,f,i,m,ret,jump
        for count in (255,256,257):
            ops=[i('int.add.wrap',['x' if k==0 else 'v'+str(k-1),'x'],[('v'+str(k),'u32')])
                 for k in range(count)]
            document=m(f('work',[('x','u32')],['u32'],[],[b('entry',[('x','u32')],ops,ret('v'+str(count-1)))]))
            with patch.dict('os.environ',{'HEPTA_HIA_AGENT_SLICE_MANIFEST':str(self.manifest)}):
                if count<=256:
                    q=prepare_edit(document,function='work',block='entry',output='v0',fields=['op'])
                    self.assertEqual(1+len(q['context']['consumers'])+len(q['context']['dependencies']),count)
                else:
                    with self.assertRaisesRegex(HIAEditRejected,'operation budget'):
                        prepare_edit(document,function='work',block='entry',output='v0',fields=['op'])
        for count in (63,64,65):
            blocks=[]
            for k in range(count):
                ops=[i('int.add.wrap',['x0','x0'],[('chosen','u32')])] if k==0 else []
                name='chosen' if k==0 else 'x'+str(k)
                blocks.append(b('b'+str(k),[('x'+str(k),'u32')],ops,
                    ret(name) if k+1==count else jump('b'+str(k+1),name)))
            document=m(f('work',[('x0','u32')],['u32'],[],blocks))
            with patch.dict('os.environ',{'HEPTA_HIA_AGENT_SLICE_MANIFEST':str(self.manifest)}):
                if count<=64:
                    q=prepare_edit(document,function='work',block='b0',output='chosen',fields=['op'])
                    self.assertEqual(1+len(q['context']['downstream']),count)
                else:
                    with self.assertRaisesRegex(HIAEditRejected,'block budget'):
                        prepare_edit(document,function='work',block='b0',output='chosen',fields=['op'])

    def test_concurrent_calls_share_no_work_or_graph_flags(self):
        cases=self.references*32
        with ThreadPoolExecutor(max_workers=8) as pool: actual=list(pool.map(lambda r:self.native.run(r[0]),cases))
        self.assertEqual(actual,[r[1] for r in cases])

    def test_standalone_syscall_filter_with_no_host_payload_parser(self):
        for wire,expected in self.references:
            with patch('json.loads',side_effect=AssertionError('host payload parser')):
                result=subprocess.run([str(self.executable)],input=wire,capture_output=True,
                    timeout=10,env={'PATH':'/nonexistent','HOME':'/nonexistent'})
            self.assertEqual((result.returncode,result.stdout,result.stderr),(0,expected,b''))
        result=subprocess.run([str(self.executable)],input=b'bad',capture_output=True,timeout=10,
                              env={'PATH':'/nonexistent','HOME':'/nonexistent'})
        self.assertEqual((result.returncode,result.stdout,result.stderr),(2,b'',b''))
        trace=self.folder/'filter.strace'
        result=subprocess.run(['/usr/bin/strace','-qq','-o',str(trace),str(self.executable)],
            input=self.references[0][0],capture_output=True,timeout=10,
            env={'PATH':'/nonexistent','HOME':'/nonexistent'})
        self.assertEqual((result.returncode,result.stdout,result.stderr),(0,self.references[0][1],b''))
        calls=re.findall(r'^([a-z0-9_]+)\(',trace.read_text(),re.MULTILINE)
        self.assertEqual(set(calls),{'execve','mmap','read','write','exit'})
        self.assertEqual(calls.count('execve'),1)
        for injection in ('read:error=EINTR:when=1','write:error=EINTR:when=1'):
            result=subprocess.run(['/usr/bin/strace','-qq','-o',str(trace),'-e','inject='+injection,str(self.executable)],
                input=self.references[0][0],capture_output=True,timeout=10)
            self.assertEqual((result.returncode,result.stdout,result.stderr),(0,self.references[0][1],b''))
        result=subprocess.run(['/usr/bin/strace','-qq','-o',str(trace),'-e','inject=mmap:error=ENOMEM:when=1',str(self.executable)],
            input=self.references[0][0],capture_output=True,timeout=10)
        self.assertEqual((result.returncode,result.stdout,result.stderr),(4,b'',b''))

    def test_explicit_manifest_failure_cannot_fall_back(self):
        from hepta.hia_edit_query import prepare_edit
        from tests.test_hia_edit_query import fixture
        with (patch.dict('os.environ',{'HEPTA_HIA_AGENT_SLICE_MANIFEST':str(self.folder/'absent.json')}),
              patch('hepta.hia_edit_query._reference_edit_slice',side_effect=AssertionError('fallback'))):
            with self.assertRaises(FileNotFoundError):
                prepare_edit(fixture(),function='calculate',block='entry',output='y',fields=['op'])


if __name__=='__main__':unittest.main()
