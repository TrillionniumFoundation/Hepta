"""Native workspace materialization never bypasses native semantic checking."""
from concurrent.futures import ThreadPoolExecutor
import copy
import ctypes
from functools import lru_cache
from hashlib import sha256
import json
from pathlib import Path
import random
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from hepta.hia_core_workspace_materialize_native import (
    NativeCoreWorkspaceMaterializer,SOURCE,SCHEMA,ARENA_BYTES,WORKSPACE_BYTES,installed_materializer,
)
from hepta.hia_core_module_graph_native import CoreModuleRejected,NativeCoreModuleGraph,link_workspace
from hepta.hia_agent_assembly import assemble_program,render_assembly
from hepta.hia_program import verify_program,execute_program
from tests.test_hia_core_module_graph_native import project,independent_case,vm as graph_vm
from tests.test_hia_program import b,c,f,i,ret

ROOT=Path(__file__).resolve().parents[1]


@lru_cache(maxsize=1)
def checked_source(raw):return assemble_program(raw)


def vm_render(wire):
    from hepta.hia_program_runtime import _Machine,_Owner,_View
    checked=checked_source(SOURCE.read_bytes());machine=_Machine(checked,20000000,16<<20,None,256)
    owners=[_Owner(-1,bytearray(wire)),_Owner(-2,bytearray(ARENA_BYTES)),_Owner(-3,bytearray(WORKSPACE_BYTES))]
    entry=next(f for f in checked.as_dict()['functions'] if f['name']=='f0')
    code=machine.invoke(entry,[_View(owners[0],False),_View(owners[1],True),_View(owners[2],True)])[0]
    return code,bytes(owners[1].data[:code]) if code<=1<<20 else None


def manual_case():
    doc=project();app=copy.deepcopy(doc['modules'][0]['core']['functions'][0]);lib=copy.deepcopy(doc['modules'][1]['core']['functions'][0])
    lib['name']='f1';app['blocks'][0]['ops'][0]['attrs']['function']='f1'
    expected=render_assembly(verify_program({'schema':'hepta.hia.program.v8','module':'core_workspace','functions':[app,lib],'exports':['work']})).encode()
    return json.dumps(doc).encode(),expected


class CoreWorkspaceMaterializerSourceTests(unittest.TestCase):
    def test_incomplete_cold_receipt_refused_before_output_creation(self):
        from tools.build_hia_core_workspace_cli import build
        with tempfile.TemporaryDirectory(prefix='hia-workspace-build-refusal-') as folder:
            root=Path(folder);compiler=root/'compiler';report=root/'cold.json';output=root/'output'
            compiler.write_bytes(b'untrusted');report.write_text('{}')
            with self.assertRaisesRegex(ValueError,'completed matching-source cold'):
                build(output,compiler,report)
            self.assertFalse(output.exists())

    def test_independent_VM_manual_names_and_complete_bytes_before_native_seed(self):
        from tools.generate_hia_core_workspace_materialize import document
        self.assertEqual(SOURCE.read_text(),render_assembly(document()))
        wire,expected=manual_case();self.assertEqual(vm_render(wire),(len(expected),expected))
        self.assertEqual(vm_render(b'{}')[0],0xffffffff)

    def test_independent_VM_packer_and_refusal_canaries_before_native_seed(self):
        from tools.generate_hia_core_workspace_cli import MAGIC,document
        from tools.qualify_hia_selfhost_cli import inspect_executable
        from tests.test_hia_core_workspace_facts_native import vm_run
        source=ROOT/'examples/hia_bootstrap/core_workspace_cli_packer.hepta'
        self.assertEqual(source.read_text(),render_assembly(document()))
        payload=b'\x31\xc0\xc3';frame=struct.pack('<4Q',MAGIC,3,3,1)+payload+payload
        size,packed=vm_run(source,frame,4096,1);self.assertEqual(size,len(packed))
        self.assertTrue(packed.endswith(payload+payload));inspect_executable(packed)
        for wire,capacity,status in [(frame,64,0xfffffffe),(frame+b'x',4096,0xffffffff),
                                    (struct.pack('<4Q',MAGIC,3,3,0)+payload+payload,4096,0xffffffff)]:
            self.assertEqual(vm_run(source,wire,capacity,1),(status,b'\xa5'*capacity))


class CoreWorkspaceMaterializerNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        wire,expected=manual_case();assert vm_render(wire)==(len(expected),expected)
        CoreWorkspaceMaterializerSourceTests().test_independent_VM_packer_and_refusal_canaries_before_native_seed()
        facts,result=independent_case();assert graph_vm(facts,len(result))==(len(result),result)
        from tools.qualify_hia_selfhost import build_seed,compile_stage
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        cls.temporary=tempfile.TemporaryDirectory(prefix='hia-workspace-materialize-');cls.folder=Path(cls.temporary.name)
        seed,_=build_seed(cls.folder);source=(ROOT/'examples/hia_bootstrap/selfhost.hepta').read_bytes()
        first,_=compile_stage(cls.folder,'B1',seed,source,image_format='seed-shared')
        compiler,_=compile_stage(cls.folder,'B2',first,source);assert first.read_bytes()==compiler.read_bytes()
        image,_=compile_stage(cls.folder,'workspace-materialize',compiler,SOURCE.read_bytes())
        cls.native=NativeCoreWorkspaceMaterializer(image.read_bytes(),sha256(image.read_bytes()).hexdigest())
        cls.compiler=NativeHiaJsonImage(compiler.read_bytes(),sha256(compiler.read_bytes()).hexdigest())
        from tools.generate_hia_core_workspace_cli import MAGIC,BUNDLE_LIMIT
        from tools.qualify_hia_selfhost_cli import inspect_executable
        packer,_=compile_stage(cls.folder,'workspace-CLI-packer',compiler,(ROOT/'examples/hia_bootstrap/core_workspace_cli_packer.hepta').read_bytes())
        packer_native=NativeHiaJsonImage(packer.read_bytes(),sha256(packer.read_bytes()).hexdigest())
        frame=struct.pack('<4Q',MAGIC,image.stat().st_size,compiler.stat().st_size,1)+image.read_bytes()+compiler.read_bytes()
        size,packed=cls.call(packer_native,frame,BUNDLE_LIMIT,1);assert 0<size<=BUNDLE_LIMIT
        inspect_executable(packed);cls.executable=cls.folder/'hia-workspace-elf'
        cls.executable.write_bytes(packed);cls.executable.chmod(0o700)
        graph,_=compile_stage(cls.folder,'workspace-reference-graph',compiler,(ROOT/'examples/hia_bootstrap/core_module_graph.hepta').read_bytes())
        cls.graph=NativeCoreModuleGraph(graph.read_bytes(),sha256(graph.read_bytes()).hexdigest())
        linker,_=compile_stage(cls.folder,'workspace-ELF-linker',compiler,(ROOT/'examples/hia_bootstrap/elf_static_linker.hepta').read_bytes())
        cls.linker=NativeHiaJsonImage(linker.read_bytes(),sha256(linker.read_bytes()).hexdigest())
        cls.manifest=cls.folder/'manifest.json'
        cls.manifest.write_text(json.dumps({'schema':SCHEMA,'source_sha256':sha256(SOURCE.read_bytes()).hexdigest(),
            'image_path':image.name,'image_sha256':cls.native.image_sha256,'compiler_sha256':cls.compiler.image_sha256}))

    @classmethod
    def tearDownClass(cls):cls.temporary.cleanup()

    @staticmethod
    def call(image,wire,capacity,scratch):
        source=ctypes.create_string_buffer(wire,max(1,len(wire)))
        output=ctypes.create_string_buffer(b'\xa5'*(capacity+64),capacity+64)
        state=ctypes.create_string_buffer(scratch+64)
        ctypes.memset(ctypes.addressof(state)+scratch,0x5a,64)
        status=image._entry(source,len(wire),output,capacity,state,scratch)
        assert output.raw[capacity:]==b'\xa5'*64
        assert state.raw[scratch:]==b'\x5a'*64
        return status,ctypes.string_at(output,status) if status<=capacity else output.raw[:capacity]

    def test_original_and_modified_real_projects_without_foreign_payload_stack(self):
        from tools.generate_hia_elf_linker import MAGIC,WORKSPACE_BYTES as LINK_SCRATCH
        cases=[]
        for inc in (1,7):
            doc=project(inc);doc['modules'][0]['core']['functions'].append(f('start',[],['u32'],[],[
                b('entry',[],[c('a','u32',41),i('call',['a'],[('result','u32')],function='work')],ret('result'))]))
            doc['modules'][0]['exports']=['start'];verified,_=link_workspace(doc,native=self.graph)
            cases.append((inc,json.dumps(doc).encode(),render_assembly(verified).encode(),execute_program(verified,'start',[])['result']))
        with patch('json.loads',side_effect=AssertionError('host JSON payload decoder')), \
             patch('hepta.hia_core_module_graph_native.link_workspace',side_effect=AssertionError('host materializer')), \
             patch('hepta.hia_program.verify_program',side_effect=AssertionError('host semantic checker')), \
             patch('hepta.hia_agent_assembly.render_assembly',side_effect=AssertionError('host renderer')):
            for inc,wire,wanted,oracle in cases:
                assembly=self.native.render(wire);self.assertEqual(assembly,wanted)
                status,obj=self.call(self.compiler,assembly,1<<20,1<<20)
                self.assertTrue(0<status<=1<<20);self.assertTrue(obj.startswith(b'\x7fELF'))
                entry=b'start';frame=struct.pack('<4Q',MAGIC,1,len(entry),0)+entry+struct.pack('<Q',len(obj))+obj
                size,elf=self.call(self.linker,frame,65536,LINK_SCRATCH);self.assertTrue(0<size<65536)
                executable=self.folder/('actual-project-'+str(inc));executable.write_bytes(elf);executable.chmod(0o700)
                actual=subprocess.run([str(executable)],capture_output=True,env={'PATH':''},timeout=3)
                self.assertEqual((actual.returncode,actual.stdout,actual.stderr),(oracle,b'',b''));self.assertEqual(oracle,41+inc)

    def test_capture_avoidance_original_public_names_and_random_declaration_order(self):
        cases=[];rng=random.Random(881)
        for n in range(32):
            doc=project(n+1);public=['work','f0','f1','public_'+('x'*121)][n%4]
            doc['modules'][0]['core']['functions'][0]['name']=public;doc['modules'][0]['exports']=[public]
            if n%2:doc['modules'].reverse()
            rng.shuffle(doc['modules'])
            verified,_=link_workspace(doc,native=self.graph)
            cases.append((json.dumps(doc,sort_keys=bool(n%3)).encode(),render_assembly(verified).encode()))
        with patch('json.loads',side_effect=AssertionError('host JSON payload decoder')):
            for wire,wanted in cases:self.assertEqual(self.native.render(wire),wanted)

    def test_policy_refusals_and_versions_are_not_silently_erased(self):
        cases=[b'null',b'{}',b'[]',b'{"entry":1,"entry":2}',b'\xff']
        for change in ('entry','private','unknown-call','cycle','schema','types','bad-field'):
            doc=project()
            if change=='entry':doc['entry']='absent'
            if change=='private':doc['modules'][1]['exports']=[]
            if change=='unknown-call':doc['modules'][0]['core']['functions'][0]['blocks'][0]['ops'][0]['attrs']['function']='missing'
            if change=='cycle':doc['modules'][1]['imports']=[{'alias':'unused','module':'app','symbol':'work'}]
            if change=='schema':
                for module in doc['modules']:module['core']['schema']='hepta.hia.program.v7'
            if change=='types':doc['modules'][0]['core']['types']=[]
            if change=='bad-field':doc['modules'][0]['core']['functions'][0]['unexpected']=0
            cases.append(json.dumps(doc).encode())
        for wire in cases:
            with self.subTest(wire=wire),self.assertRaises(CoreModuleRejected):self.native.render(wire)

    def test_invalid_SSA_and_live_loans_reach_actual_native_semantic_refusal(self):
        undefined=project();undefined['modules'][1]['core']['functions'][0]['blocks'][0]['ops'][1]['args'][0]='undefined_SSA'
        loan=f('start',[],['u32'],['alloc','read','write','trap'],[b('entry',[],[
            c('n','usize',1),i('buffer.new',['n'],[('owner','buffer')]),i('borrow.mut',['owner'],[('view','mutbuf')]),
            i('owner.drop',['owner']),c('zero','u32',0)],ret('zero'))])
        borrowed={'schema':'hepta.hia.core-workspace.v1','entry':'app','modules':[
            {'core':{'schema':'hepta.hia.program.v8','module':'app','functions':[loan]},'exports':['start'],'imports':[]}]}
        for doc in (undefined,borrowed):
            assembly=self.native.render(json.dumps(doc).encode())
            status,output=self.call(self.compiler,assembly,1<<20,1<<20)
            self.assertEqual(status,0xffffffff);self.assertEqual(output,b'\xa5'*(1<<20))

    def test_buffer_guards_and_private_calls_keep_exact_output(self):
        wire,wanted=manual_case()
        for capacity,scratch in [(ARENA_BYTES-1,WORKSPACE_BYTES),(ARENA_BYTES,WORKSPACE_BYTES-1)]:
            code,output=self.call(self.native,wire,capacity,scratch)
            self.assertEqual(code,0xfffffffe);self.assertEqual(output,b'\xa5'*capacity)
        with ThreadPoolExecutor(max_workers=4) as pool:
            self.assertEqual(list(pool.map(self.native.render,[wire]*16)),[wanted]*16)

    def test_manifest_source_binding_and_no_default_fallback(self):
        import hepta.hia_core_workspace_materialize_native as module
        source=self.folder/'source-copy';source.write_bytes(SOURCE.read_bytes())
        with patch.object(module,'SOURCE',source):
            wire,wanted=manual_case();self.assertEqual(installed_materializer(self.manifest).render(wire),wanted)
            source.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'source identity'):installed_materializer(self.manifest)

    def run_cli(self,wire,*args):
        return subprocess.run([str(self.executable),*args],input=wire,capture_output=True,env={'PATH':''},timeout=20)

    def test_copied_standalone_pipeline_has_no_payload_interpreter_or_children(self):
        wire=json.dumps(project()).encode();assembly=self.native.render(wire)
        size,expected=self.call(self.compiler,assembly,1<<20,1<<20);self.assertTrue(0<size<=1<<20)
        copied=self.folder/'copied';copied.mkdir();target=copied/'workspace-elf'
        shutil.copyfile(self.executable,target);target.chmod(0o700)
        tracer=shutil.which('strace');self.assertIsNotNone(tracer);trace=self.folder/'standalone.trace'
        result=subprocess.run([tracer,'-f','-e','trace=execve,openat,clone,fork,vfork','-o',str(trace),str(target)],
            input=wire,capture_output=True,env={'PATH':''},cwd=copied,timeout=20)
        self.assertEqual((result.returncode,result.stdout,result.stderr),(0,expected,b''))
        text=trace.read_text();self.assertEqual(text.count('execve('),1)
        for forbidden in ('openat(','clone(','fork(','vfork('):self.assertNotIn(forbidden,text)
        bad_core=project();bad_core['modules'][1]['core']['functions'][0]['blocks'][0]['ops'][1]['args'][0]='undefined_SSA'
        duplicate=project();duplicate['modules'].append(copy.deepcopy(duplicate['modules'][0]))
        for body in (b'',b'{}',b'null',json.dumps(bad_core).encode(),json.dumps(duplicate).encode()):
            r=self.run_cli(body);self.assertEqual((r.returncode,r.stdout),(2,b''))
        r=self.run_cli(wire,'unexpected');self.assertEqual((r.returncode,r.stdout),(64,b''))
        r=self.run_cli(b' '*(8<<20)+b'0');self.assertEqual((r.returncode,r.stdout),(3,b''))

    def test_standalone_actual_EINTR_and_real_partial_write(self):
        tracer=shutil.which('strace');self.assertIsNotNone(tracer)
        wire=json.dumps(project()).encode();trace=self.folder/'eintr.trace';expected=self.run_cli(wire).stdout
        result=subprocess.run([tracer,'-qq','-o',str(trace),'-e','inject=read:error=EINTR:when=1',
            '-e','inject=write:error=EINTR:when=1',str(self.executable)],input=wire,capture_output=True,env={'PATH':''},timeout=20)
        self.assertEqual((result.returncode,result.stdout,result.stderr),(0,expected,b''));self.assertEqual(trace.read_bytes().count(b'(INJECTED)'),2)
        doc=project()
        # Two project functions plus 126 unused functions reach the existing
        # native compiler's 128-function profile without broadening that cap.
        for n in range(126):doc['modules'][1]['core']['functions'].append(f('unused_'+str(n),[],['u32'],[],[b('entry',[],[c('v','u32',n)],ret('v'))]))
        wire=json.dumps(doc).encode();r=self.run_cli(wire);self.assertEqual(r.returncode,0);expected=r.stdout
        self.assertGreater(len(expected),4096)
        over=copy.deepcopy(doc);over['modules'][1]['core']['functions'].append(f('one_past',[],['u32'],[],[b('entry',[],[c('v','u32',0)],ret('v'))]))
        refused=self.run_cli(json.dumps(over).encode());self.assertEqual((refused.returncode,refused.stdout),(2,b''))
        import fcntl,os
        read_fd,write_fd=os.pipe()
        try:
            fcntl.fcntl(write_fd,fcntl.F_SETPIPE_SZ,4096)
            fcntl.fcntl(write_fd,fcntl.F_SETFL,fcntl.fcntl(write_fd,fcntl.F_GETFL)|os.O_NONBLOCK)
            r=subprocess.run([str(self.executable)],input=wire,stdout=write_fd,stderr=subprocess.PIPE,env={'PATH':''},timeout=20)
            os.close(write_fd);write_fd=-1;prefix=b''
            while chunk:=os.read(read_fd,65536):prefix+=chunk
            self.assertEqual((r.returncode,r.stderr),(4,b''));self.assertGreater(len(prefix),0)
            self.assertLess(len(prefix),len(expected));self.assertEqual(prefix,expected[:len(prefix)])
        finally:
            os.close(read_fd)
            if write_fd!=-1:os.close(write_fd)


if __name__=='__main__':unittest.main()
