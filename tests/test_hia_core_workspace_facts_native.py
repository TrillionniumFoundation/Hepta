"""Independent VM and actual native workspace JSON transport controls.

Fact normalization is not whole-Core verification or module graph admission.
"""
from concurrent.futures import ThreadPoolExecutor
import copy
import ctypes
from functools import lru_cache
from hashlib import sha256
import json
import os
from pathlib import Path
import random
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_core_workspace_facts_native import (
    NativeCoreWorkspaceFacts, SOURCE, SCHEMA, ARENA_BYTES, WORKSPACE_BYTES,
    installed_workspace_facts,
)
from hepta.hia_core_module_graph_native import encode_workspace, CoreModuleRejected
from tools.generate_hia_core_workspace_facts import document
from tools.generate_hia_core_workspace_facts_cli import MAGIC, document as packer_document
from tests.test_hia_core_module_graph_native import project

ROOT = Path(__file__).resolve().parents[1]
PACKER = ROOT / 'examples/hia_bootstrap/core_workspace_facts_packer.hepta'


@lru_cache(maxsize=2)
def checked(raw):
    from hepta.hia_agent_assembly import assemble_program
    return assemble_program(raw)


def vm_run(source, wire, capacity, scratch):
    from hepta.hia_program_runtime import _Machine, _Owner, _View
    program = checked(source.read_bytes())
    machine = _Machine(program, 20000000, 16 << 20, None, 256)
    owners = [_Owner(-1, bytearray(wire)), _Owner(-2, bytearray(b'\xa5' * capacity)),
              _Owner(-3, bytearray(scratch))]
    entry = next(f for f in program.as_dict()['functions'] if f['name'] == 'f0')
    code = machine.invoke(entry, [_View(owners[0], False), _View(owners[1], True), _View(owners[2], True)])[0]
    return code, bytes(owners[1].data[:code]) if code <= capacity else bytes(owners[1].data)


class CoreWorkspaceFactsSourceTests(unittest.TestCase):
    def test_exact_sources_and_independent_VM_fact_bytes(self):
        from hepta.hia_agent_assembly import render_assembly
        self.assertEqual(SOURCE.read_text(), render_assembly(document()))
        self.assertEqual(PACKER.read_text(), render_assembly(packer_document()))
        # One module/function, independently laid out; no host normalizer oracle.
        doc = {'schema':'hepta.hia.core-workspace.v1','entry':'a','modules':[
            {'core':{'schema':'hepta.hia.program.v8','module':'a',
                     'functions':[{'name':'f','blocks':[]}]}, 'imports':[], 'exports':['f']}]}
        expected = struct.pack('<10Q', int.from_bytes(b'HIAMOD01','little'),1,1,0,0,1,4,0,1,0)
        expected += struct.pack('<4Q',1,1,0,1) + struct.pack('<4Q',0,2,1,0)
        expected += struct.pack('<3Q',0,3,1) + b'aaff'
        self.assertEqual(vm_run(SOURCE,json.dumps(doc).encode(),32768,WORKSPACE_BYTES),
                         (len(expected),expected))
        self.assertEqual(vm_run(SOURCE,b'{}',32768,WORKSPACE_BYTES)[0],0xffffffff)

    def test_independent_VM_packer_before_new_seed_and_refusal_canaries(self):
        from tools.qualify_hia_selfhost_cli import inspect_executable
        payload=b'\x31\xc0\xc3'; frame=struct.pack('<QQ',MAGIC,len(payload))+payload
        size,raw=vm_run(PACKER,frame,4096,1)
        self.assertEqual(size,len(raw)); self.assertTrue(raw.endswith(payload)); inspect_executable(raw)
        for wire,cap,code in [(frame,64,0xfffffffe),(frame+b'x',4096,0xffffffff),(b'bad',4096,0xffffffff)]:
            self.assertEqual(vm_run(PACKER,wire,cap,1),(code,b'\xa5'*cap))


class CoreWorkspaceFactsNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Run both independent interpreters before constructing this native seed.
        source_tests=CoreWorkspaceFactsSourceTests()
        source_tests.test_exact_sources_and_independent_VM_fact_bytes()
        source_tests.test_independent_VM_packer_before_new_seed_and_refusal_canaries()
        from tools.qualify_hia_selfhost import build_seed, compile_stage, invoke
        from tools.qualify_hia_selfhost_cli import inspect_executable
        cls.temporary=tempfile.TemporaryDirectory(prefix='hia-workspace-json-')
        cls.folder=Path(cls.temporary.name)
        seed,_=build_seed(cls.folder)
        source=(ROOT/'examples/hia_bootstrap/selfhost.hepta').read_bytes()
        first,_=compile_stage(cls.folder,'B1',seed,source,image_format='seed-shared')
        cls.compiler,_=compile_stage(cls.folder,'B2',first,source)
        assert first.read_bytes()==cls.compiler.read_bytes()
        image,cls.receipt=compile_stage(cls.folder,'workspace-json',cls.compiler,SOURCE.read_bytes())
        cls.image=NativeCoreWorkspaceFacts(image.read_bytes(),sha256(image.read_bytes()).hexdigest())
        cls.manifest=cls.folder/'manifest.json'
        cls.manifest.write_text(json.dumps({'schema':SCHEMA,'source_sha256':sha256(SOURCE.read_bytes()).hexdigest(),
            'image_path':image.name,'image_sha256':cls.image.image_sha256,
            'compiler_sha256':sha256(cls.compiler.read_bytes()).hexdigest()}))
        packer,_=compile_stage(cls.folder,'workspace-json-packer',cls.compiler,PACKER.read_bytes())
        frame=struct.pack('<QQ',MAGIC,image.stat().st_size)+image.read_bytes()
        result,packed=invoke(cls.folder,'workspace-json-pack',packer,frame)
        size=result['core_u32']; assert 0<size<=1<<20
        raw=packed[:size]; inspect_executable(raw)
        assert vm_run(PACKER,frame,len(frame)+4096,1)==(size,raw)
        cls.executable=cls.folder/'hia-workspace-json'
        cls.executable.write_bytes(raw); cls.executable.chmod(0o700)
        from tests.test_hia_core_module_graph_native import independent_case, vm
        from hepta.hia_core_module_graph_native import NativeCoreModuleGraph, SOURCE as GRAPH_SOURCE
        facts,wanted=independent_case(); assert vm(facts,len(wanted))==(len(wanted),wanted)
        graph,_=compile_stage(cls.folder,'workspace-graph',cls.compiler,GRAPH_SOURCE.read_bytes())
        cls.graph=NativeCoreModuleGraph(graph.read_bytes(),sha256(graph.read_bytes()).hexdigest())

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_exact_bytes_without_host_decoder_or_fact_encoder(self):
        rng=random.Random(878); cases=[]
        for n in range(64):
            doc=project(n%8+1)
            for module in doc['modules']: module['core']['schema']='hepta.hia.program.v'+str(n%8+1)
            if n%2: doc['modules'].reverse()
            doc['modules'][0]['core']['functions'][0]['ignored_metadata']=[None,True,rng.randrange(1000),'é']
            cases.append((json.dumps(doc,sort_keys=bool(n%3),ensure_ascii=bool(n%2)).encode(),encode_workspace(doc)[0]))
        with patch('json.loads',side_effect=AssertionError('foreign payload decoder')), \
             patch('hepta.hia_core_module_graph_native.encode_workspace',side_effect=AssertionError('foreign fact traversal')):
            for wire,wanted in cases: self.assertEqual(self.image.normalize(wire),wanted)

    def test_malformed_framing_is_not_module_policy_admission(self):
        bad=[b'null',b'[]',b'{}',b'',b'{"schema":1,"schem\\u0061":2}',b'{} false',b'\xff']
        for mutation in ('extra','nominal','mixed','import','function','ops'):
            doc=project()
            if mutation=='extra': doc['extra']=0
            if mutation=='nominal': doc['modules'][0]['core']['types']=[]
            if mutation=='mixed': doc['modules'][1]['core']['schema']='hepta.hia.program.v7'
            if mutation=='import': doc['modules'][0]['imports'][0]['alias']=True
            if mutation=='function': doc['modules'][0]['core']['functions'][0]['name']=1
            if mutation=='ops': doc['modules'][0]['core']['functions'][0]['blocks'][0]['ops']={}
            bad.append(json.dumps(doc).encode())
        for wire in bad:
            with self.subTest(wire=wire),self.assertRaises(CoreModuleRejected): self.image.normalize(wire)
        # Framing success deliberately DOES NOT grant spelling/visibility/Core verification.
        doc=project(); doc['entry']='not a valid identifier'
        self.assertEqual(self.image.normalize(json.dumps(doc).encode()),encode_workspace(doc)[0])
        for wire in (None,'{}',bytearray(b'{}'),b' '*(8<<20)+b'0'):
            with self.assertRaises(CoreModuleRejected): self.image.normalize(wire)

    def test_complete_bounded_counts_and_one_past_each_limit(self):
        def minimal():
            return {'schema':'hepta.hia.core-workspace.v1','entry':'m0','modules':[
                {'core':{'schema':'hepta.hia.program.v8','module':'m0',
                         'functions':[{'name':'f0','blocks':[]}]},'imports':[],'exports':[]}]}
        for field,limit in [('modules',1024),('functions',1024),('imports',4096),('calls',16384),('exports',1024)]:
            for count in (limit,limit+1):
                doc=minimal(); module=doc['modules'][0]
                if field=='modules':
                    doc['modules']=[{'core':{'schema':'hepta.hia.program.v8','module':'m'+str(n),'functions':[]},
                                     'imports':[],'exports':[]} for n in range(count)]
                if field=='functions': module['core']['functions']=[{'name':'f'+str(n),'blocks':[]} for n in range(count)]
                if field=='imports': module['imports']=[{'alias':'a'+str(n),'module':'m0','symbol':'f0'} for n in range(count)]
                if field=='calls': module['core']['functions'][0]['blocks']=[{'ops':[{'op':'call','attrs':{'function':'f0'}} for _ in range(count)]}]
                if field=='exports': module['exports']=['f0']*count
                wire=json.dumps(doc,separators=(',',':')).encode()
                with self.subTest(field=field,count=count):
                    if count==limit:
                        self.assertEqual(self.image.normalize(wire),encode_workspace(wire)[0])
                    else:
                        with self.assertRaises(CoreModuleRejected): self.image.normalize(wire)
                        with self.assertRaises(CoreModuleRejected): encode_workspace(wire)

    def test_native_facts_feed_native_policy_without_host_decoder_or_encoder(self):
        from hepta.hia_core_module_graph_native import RESULT,NONE
        wanted=struct.pack('<14Q',RESULT,2,2,1,1,2,0,0,1,0,1,1,0,NONE)
        wire=json.dumps(project()).encode()
        invalid=project(); invalid['entry']='not a valid identifier'; invalid_wire=json.dumps(invalid).encode()
        with patch('json.loads',side_effect=AssertionError('foreign payload decoder')), \
             patch('hepta.hia_core_module_graph_native.encode_workspace',side_effect=AssertionError('foreign fact traversal')):
            self.assertEqual(self.graph.run(self.image.normalize(wire)),wanted)
            with self.assertRaises(CoreModuleRejected): self.graph.run(self.image.normalize(invalid_wire))

    def test_capacity_guards_and_private_concurrency(self):
        wire=json.dumps(project()).encode()
        for output_size,scratch_size in [(64,WORKSPACE_BYTES),(ARENA_BYTES,WORKSPACE_BYTES-1)]:
            s=ctypes.create_string_buffer(wire)
            o=ctypes.create_string_buffer(b'\xa5'*(output_size+64),output_size+64)
            w=ctypes.create_string_buffer(b'\x5a'*(scratch_size+64),scratch_size+64)
            self.assertEqual(self.image._entry(s,len(wire),o,output_size,w,scratch_size),0xfffffffe)
            self.assertEqual(o.raw[output_size:],b'\xa5'*64); self.assertEqual(w.raw[scratch_size:],b'\x5a'*64)
        values=[json.dumps(project(n%8+1)).encode() for n in range(16)]
        expected=[encode_workspace(w)[0] for w in values]
        with ThreadPoolExecutor(max_workers=4) as pool:
            self.assertEqual(list(pool.map(self.image.normalize,values)),expected)

    def run_cli(self,wire,*args):
        return subprocess.run([str(self.executable),*args],input=wire,capture_output=True,
                              env={'PATH':''},timeout=20)

    def test_copied_standalone_no_interpreter_opens_or_children(self):
        copied=self.folder/'copied'; copied.mkdir()
        executable=copied/'workspace'; shutil.copyfile(self.executable,executable); executable.chmod(0o700)
        wire=json.dumps(project()).encode(); wanted=encode_workspace(wire)[0]
        tracer=shutil.which('strace'); self.assertIsNotNone(tracer)
        trace=self.folder/'syscalls.log'
        result=subprocess.run([tracer,'-f','-e','trace=execve,openat,clone,fork,vfork','-o',str(trace),str(executable)],
            input=wire,capture_output=True,cwd=copied,env={'PATH':''},timeout=20)
        self.assertEqual((result.returncode,result.stdout,result.stderr),(0,wanted,b''))
        text=trace.read_text(); self.assertEqual(text.count('execve('),1)
        for forbidden in ('openat(','clone(','fork(','vfork('): self.assertNotIn(forbidden,text)
        for wire in (b'',b'{}',b'null',b'{"schema":1,"schema":2}'):
            r=self.run_cli(wire); self.assertEqual((r.returncode,r.stdout),(2,b''))
        r=self.run_cli(b' '*(8<<20)+b'0'); self.assertEqual((r.returncode,r.stdout),(3,b''))
        r=self.run_cli(b'{}','extra'); self.assertEqual((r.returncode,r.stdout),(64,b''))

    def test_real_interrupted_reads_writes_and_nonblocking_partial_output(self):
        tracer=shutil.which('strace'); self.assertIsNotNone(tracer)
        wire=json.dumps(project()).encode(); trace=self.folder/'eintr.log'
        result=subprocess.run([tracer,'-qq','-o',str(trace),'-e','inject=read:error=EINTR:when=1',
            '-e','inject=write:error=EINTR:when=1',str(self.executable)],input=wire,capture_output=True,
            env={'PATH':''},timeout=20)
        self.assertEqual((result.returncode,result.stdout,result.stderr),(0,encode_workspace(wire)[0],b''))
        self.assertEqual(trace.read_bytes().count(b'(INJECTED)'),2)
        import fcntl
        doc=project(); doc['entry']='a'*16384; wire=json.dumps(doc).encode(); wanted=encode_workspace(wire)[0]
        read_fd,write_fd=os.pipe()
        try:
            fcntl.fcntl(write_fd,fcntl.F_SETPIPE_SZ,4096)
            fcntl.fcntl(write_fd,fcntl.F_SETFL,fcntl.fcntl(write_fd,fcntl.F_GETFL)|os.O_NONBLOCK)
            r=subprocess.run([str(self.executable)],input=wire,stdout=write_fd,stderr=subprocess.PIPE,env={'PATH':''},timeout=20)
            os.close(write_fd); write_fd=-1; prefix=b''
            while chunk:=os.read(read_fd,65536): prefix+=chunk
            self.assertEqual((r.returncode,r.stderr),(4,b'')); self.assertGreater(len(prefix),0)
            self.assertLess(len(prefix),len(wanted)); self.assertEqual(prefix,wanted[:len(prefix)])
        finally:
            os.close(read_fd)
            if write_fd!=-1: os.close(write_fd)

    def test_manifest_binding_and_incomplete_builder_refuses_before_output(self):
        import hepta.hia_core_workspace_facts_native as native
        source=self.folder/'source-copy'; source.write_bytes(SOURCE.read_bytes())
        with patch.object(native,'SOURCE',source):
            self.assertEqual(installed_workspace_facts(self.manifest).normalize(json.dumps(project()).encode()),
                             encode_workspace(project())[0])
            source.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'source identity'): installed_workspace_facts(self.manifest)
        from tools.build_hia_core_workspace_facts import build
        failed=self.folder/'not-cold.json'; failed.write_text('{"status":"FAIL"}')
        target=self.folder/'refused-build'
        with self.assertRaises(ValueError): build(target,self.compiler,failed)
        self.assertFalse(target.exists())


if __name__=='__main__':
    unittest.main()
