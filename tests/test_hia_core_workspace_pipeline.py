"""The current workspace JSON image must reach native semantic compilation."""
import copy
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import resource
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from tools.generate_hia_core_workspace_pipeline import MAGIC,BUNDLE_LIMIT,template,document
from hepta.hia_agent_assembly import assemble_program,render_assembly
from tests.test_hia_core_module_graph_native import project
from tests.test_hia_program import b,c,f,i,ret

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'examples/hia_bootstrap/core_workspace_pipeline_packer.hepta'


def frame(workspace,admission,frontend,compiler,profile=1):
    return struct.pack('<6Q',MAGIC,len(workspace),len(admission),len(frontend),len(compiler),profile)+workspace+admission+frontend+compiler


def expected_image(workspace,admission,frontend,compiler):
    prefix,holes=template();data=bytearray(prefix+workspace+admission+frontend+compiler)
    struct.pack_into('<QQ',data,96,len(data),len(data))
    for name,start in [('workspace',len(prefix)),('admission',len(prefix)+len(workspace)),
                       ('frontend',len(prefix)+len(workspace)+len(admission)),
                       ('compiler',len(prefix)+len(workspace)+len(admission)+len(frontend))]:
        struct.pack_into('<i',data,holes[name],start-holes[name]-4)
    return bytes(data)


def vm_pack(wire,capacity):
    from hepta.hia_program_runtime import _Machine,_Owner,_View
    checked=assemble_program(SOURCE.read_bytes());machine=_Machine(checked,2000000,16<<20,None,256)
    owners=[_Owner(-1,bytearray(wire)),_Owner(-2,bytearray(b'\xa5'*capacity)),_Owner(-3,bytearray())]
    entry=next(fn for fn in checked.as_dict()['functions'] if fn['name']=='f0')
    status=machine.invoke(entry,[_View(owners[0],False),_View(owners[1],True),_View(owners[2],True)])[0]
    return status,bytes(owners[1].data[:status]) if status<=capacity else bytes(owners[1].data)


class CoreWorkspacePipelineSourceTests(unittest.TestCase):
    def test_actual_kernel_code_seals_without_named_fcntl_constants(self):
        import fcntl
        from tools.compile_hia_core_workspace import _seal_code_descriptor
        absent={'F_ADD_SEALS','F_GET_SEALS','F_SEAL_WRITE','F_SEAL_GROW','F_SEAL_SHRINK','F_SEAL_SEAL'}
        descriptor=os.memfd_create('hia-workspace-seal-control',os.MFD_ALLOW_SEALING)
        try:
            os.write(descriptor,b'actual kernel seal control')
            remaining={name:value for name,value in vars(fcntl).items() if name not in absent}
            with patch.dict(fcntl.__dict__,remaining,clear=True):
                _seal_code_descriptor(descriptor)
            self.assertEqual(fcntl.fcntl(descriptor,1034)&15,15)
            with self.assertRaises(PermissionError):os.write(descriptor,b'forbidden')
        finally:os.close(descriptor)

    def test_incomplete_or_untyped_kernel_seal_readback_refuses(self):
        import fcntl
        from tools.compile_hia_core_workspace import _seal_code_descriptor
        actual=fcntl.fcntl
        for observed in (0,7,True,15.0):
            with self.subTest(observed=observed):
                descriptor=os.memfd_create('hia-workspace-seal-refusal',os.MFD_ALLOW_SEALING)
                try:
                    os.write(descriptor,b'actual kernel seal control')
                    def readback(fd,command,*arguments):
                        return observed if command==1034 else actual(fd,command,*arguments)
                    with patch.object(fcntl,'fcntl',side_effect=readback):
                        with self.assertRaisesRegex(OSError,'complete kernel seals'):
                            _seal_code_descriptor(descriptor)
                finally:os.close(descriptor)

    def test_incomplete_builder_refuses_before_output_creation_and_no_mixed_selection(self):
        from tools.build_hia_core_workspace_pipeline import build
        from tools.compile_hia_core_workspace import compile_workspace
        with tempfile.TemporaryDirectory(prefix='hia-pipeline-cold-refusal-') as folder:
            root=Path(folder);compiler=root/'compiler';cold=root/'cold.json';output=root/'output'
            compiler.write_bytes(b'untrusted');cold.write_text('{}')
            with self.assertRaisesRegex(ValueError,'completed matching-source cold'):
                build(output,compiler,cold)
            self.assertFalse(output.exists())
            with self.assertRaisesRegex(ValueError,'no mixed image or fallback'):
                compile_workspace(b'{}',root/'graph',None,None,output,pipeline_manifest=root/'manifest')
            self.assertFalse(output.exists())

    def test_independent_VM_complete_packer_bytes_before_new_native_seed(self):
        self.assertEqual(SOURCE.read_text(),render_assembly(document()))
        from tools.qualify_hia_selfhost_cli import inspect_executable
        parts=(b'\xc3',b'\x31\xc0\xc3',b'\x90\xc3',b'\x90\x90\x31\xc0\xc3')
        wire=frame(*parts);wanted=expected_image(*parts)
        self.assertEqual(vm_pack(wire,len(wanted)+8),(len(wanted),wanted));inspect_executable(wanted)
        for bad,capacity,status in [(wire,len(wanted)-1,0xfffffffe),(wire+b'x',4096,0xffffffff),
            (frame(*parts,profile=0),4096,0xffffffff),(frame(*parts,profile=2),4096,0xffffffff),
            (frame(b'',*parts[1:]),4096,0xffffffff),(frame(parts[0],b'',*parts[2:]),4096,0xffffffff),
            (struct.pack('<Q',int.from_bytes(b'HIAWCP01','little'))+wire[8:],4096,0xffffffff),
            (b'',4096,0xffffffff)]:
            self.assertEqual(vm_pack(bad,capacity),(status,b'\xa5'*capacity))


class CoreWorkspacePipelineNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        CoreWorkspacePipelineSourceTests().test_independent_VM_complete_packer_bytes_before_new_native_seed()
        from tests.test_hia_core_workspace_json_native import CoreWorkspaceJsonSourceTests
        CoreWorkspaceJsonSourceTests().test_complete_independent_vm_before_any_native_image()
        from tests.test_hia_core_admission_native import VALID,borrowed_owner,interpreted,wire
        assert interpreted(wire(VALID))==0 and interpreted(wire(borrowed_owner()))==0xfffffff8
        from tools.qualify_hia_selfhost import build_seed,compile_stage
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        root=os.environ.get('HEPTA_HIA_WORKSPACE_PIPELINE_EVIDENCE')
        cls.temporary=None
        if root:cls.folder=Path(root);cls.folder.mkdir(mode=0o700)
        else:cls.temporary=tempfile.TemporaryDirectory(prefix='hia-workspace-pipeline-');cls.folder=Path(cls.temporary.name)
        seed,_=build_seed(cls.folder);source=(ROOT/'examples/hia_bootstrap/selfhost.hepta').read_bytes()
        first,_=compile_stage(cls.folder,'B1',seed,source,image_format='seed-shared')
        compiler,_=compile_stage(cls.folder,'B2',first,source);assert first.read_bytes()==compiler.read_bytes()
        def load(path):
            raw=path.read_bytes();return NativeHiaJsonImage(raw,sha256(raw).hexdigest())
        cls.compiler=load(compiler);images={}
        for name,path in [('workspace','core_workspace_json'),('admission','core_admission'),('frontend','core_json_frontend'),
                          ('packer','core_workspace_pipeline_packer'),('linker','elf_static_linker')]:
            image,_=compile_stage(cls.folder,name,compiler,(ROOT/'examples/hia_bootstrap'/ (path+'.hepta')).read_bytes())
            images[name]=image.read_bytes()
        cls.packer=NativeHiaJsonImage(images['packer'],sha256(images['packer']).hexdigest())
        cls.linker=NativeHiaJsonImage(images['linker'],sha256(images['linker']).hexdigest())
        from hepta.hia_core_workspace_json_native import NativeCoreWorkspaceJson
        cls.workspace=NativeCoreWorkspaceJson(images['workspace'],sha256(images['workspace']).hexdigest())
        parts=(images['workspace'],images['admission'],images['frontend'],compiler.read_bytes());wanted=expected_image(*parts)
        cls.parts=parts
        size,packed=cls.call(cls.packer,frame(*parts),BUNDLE_LIMIT,0)
        assert size==len(wanted) and packed==wanted
        cls.executable=cls.folder/'hia-workspace-compile';cls.executable.write_bytes(packed);cls.executable.chmod(0o700)
        cls.source_pins={name:sha256((ROOT/'examples/hia_bootstrap'/ (path+'.hepta')).read_bytes()).hexdigest()
            for name,path in [('workspace','core_workspace_json'),('admission','core_admission'),('frontend','core_json_frontend'),
                              ('packer','core_workspace_pipeline_packer'),('compiler','selfhost')]}
        (cls.folder/'development-build.json').write_text(json.dumps({'status':'DEVELOPMENT_NOT_COLD_QUALIFICATION',
            'source_sha256':cls.source_pins,'image_sha256':{n:sha256(v).hexdigest() for n,v in images.items()},
            'compiler_image_sha256':cls.compiler.image_sha256,'executable_sha256':sha256(packed).hexdigest(),
            'bundle_limit':BUNDLE_LIMIT,'compiler_caps_unchanged':True,'whole_native_delivery_qualified':False},indent=2)+'\n')
        cls.qualified_manifest=None

    def qualified_public_bridge(self):
        from tools.build_hia_core_workspace_pipeline import build
        cls=type(self)
        if cls.qualified_manifest is None:
            selected=os.environ.get('HEPTA_HIA_CORE_MODULE_GRAPH_COLD_REPORT')
            if not selected:self.skipTest('native public workspace custody requires matching cold report')
            cold=Path(selected);report=json.loads(cold.read_bytes())
            nested=json.loads(Path(report['nested_report']).read_bytes())
            compiler=Path(nested['generations'][-1]['produced_image'])
            executable=build(cls.folder/'qualified-public-bridge',compiler,cold)
            cls.qualified_manifest=executable.parent/'build.json'
        return cls.qualified_manifest

    def test_public_pipeline_seals_actual_native_code_without_named_constants(self):
        import fcntl
        from tools.compile_hia_core_workspace import compile_pipeline
        manifest=self.qualified_public_bridge();wire=json.dumps(project()).encode()
        expected=self.run_cli(wire);self.assertEqual((expected.returncode,expected.stderr),(0,b''))
        absent={'F_ADD_SEALS','F_GET_SEALS','F_SEAL_WRITE','F_SEAL_GROW','F_SEAL_SHRINK','F_SEAL_SEAL'}
        remaining={name:value for name,value in vars(fcntl).items() if name not in absent}
        with patch.dict(fcntl.__dict__,remaining,clear=True):
            image=compile_pipeline(wire,manifest,self.folder/'sealed-public-output')
        self.assertEqual(image.read_bytes(),expected.stdout)
        receipt=json.loads((image.parent/'workspace.receipt.json').read_bytes())
        self.assertIs(receipt['sealed_code_descriptor'],True)

    def test_public_pipeline_refuses_incomplete_seals_before_exec_and_closes_fd(self):
        import fcntl
        from tools.compile_hia_core_workspace import compile_pipeline
        manifest=self.qualified_public_bridge();opened=[];actual_create=os.memfd_create;actual_fcntl=fcntl.fcntl
        def create(*arguments,**keywords):
            descriptor=actual_create(*arguments,**keywords);opened.append(descriptor);return descriptor
        def incomplete(fd,command,*arguments):
            return 7 if command==1034 else actual_fcntl(fd,command,*arguments)
        output=self.folder/'refused-public-output'
        with patch.object(os,'memfd_create',side_effect=create),patch.object(fcntl,'fcntl',side_effect=incomplete), \
             patch('subprocess.run',side_effect=AssertionError('execution before complete kernel seals')) as execute:
            with self.assertRaisesRegex(OSError,'complete kernel seals'):
                compile_pipeline(json.dumps(project()).encode(),manifest,output)
            execute.assert_not_called()
        self.assertEqual(len(opened),1)
        for descriptor in opened:
            with self.assertRaises(OSError):os.fstat(descriptor)
        self.assertFalse(output.exists())

    @classmethod
    def tearDownClass(cls):
        if cls.temporary:cls.temporary.cleanup()

    @staticmethod
    def call(image,wire,capacity,scratch):
        source=ctypes.create_string_buffer(wire,max(1,len(wire)))
        output=ctypes.create_string_buffer(b'\xa5'*(capacity+64),capacity+64)
        state=ctypes.create_string_buffer(scratch+64);ctypes.memset(ctypes.addressof(state)+scratch,0x5a,64)
        status=image._entry(source,len(wire),output,capacity,state,scratch)
        assert output.raw[capacity:]==b'\xa5'*64 and state.raw[scratch:]==b'\x5a'*64
        return status,ctypes.string_at(output,status) if status<=capacity else output.raw[:capacity]

    @staticmethod
    def native_limits():
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        resource.setrlimit(resource.RLIMIT_CPU,(10,10))
        resource.setrlimit(resource.RLIMIT_AS,(256<<20,256<<20))

    def run_cli(self,wire,*args,**kwargs):
        kwargs.setdefault('preexec_fn',self.native_limits)
        return subprocess.run([str(self.executable),*args],input=wire,capture_output=True,env={'PATH':''},timeout=20,**kwargs)

    def test_complete_Core_gate_is_mandatory_before_frontend_compiler_and_has_no_fallback(self):
        # The real four-image pipeline accepts this workspace. A selected Core
        # image refusal must stop it, even though the unchanged compiler would
        # admit it. This observes the actual native call, not manifest prose.
        wire=json.dumps(project()).encode()
        self.assertEqual(self.run_cli(wire).returncode,0)
        for status,expected in ((0xfffffff8,2),(0xfffffffe,3),(0xfffffffd,2)):
            admission=b'\xb8'+struct.pack('<I',status)+b'\xc3'
            parts=(self.parts[0],admission,*self.parts[2:])
            size,raw=self.call(self.packer,frame(*parts),BUNDLE_LIMIT,0)
            self.assertEqual((size,raw),(len(expected_image(*parts)),expected_image(*parts)))
            target=self.folder/('mandatory-core-gate-'+str(status));target.write_bytes(raw);target.chmod(0o700)
            result=subprocess.run([str(target)],input=wire,capture_output=True,env={'PATH':''},timeout=20,preexec_fn=self.native_limits)
            self.assertEqual((result.returncode,result.stdout,result.stderr),(expected,b'',b''))

    def test_copied_native_pipeline_and_actual_original_modified_projects(self):
        from hepta.hia_core_workspace_json_native import link_workspace
        from hepta.hia_program import execute_program
        from tools.generate_hia_elf_linker import MAGIC as LINK_MAGIC,WORKSPACE_BYTES as LINK_SCRATCH
        cases=[]
        for inc in (1,7):
            doc=project(inc);doc['modules'][0]['core']['functions'].append(f('start',[],['u32'],[],[
                b('entry',[],[c('a','u32',41),i('call',['a'],[('v','u32')],function='work')],ret('v'))]))
            doc['modules'][0]['exports']=['start'];wire=json.dumps(doc).encode()
            checked,_=link_workspace(wire,native=self.workspace);assembly=render_assembly(checked).encode()
            oracle=execute_program(checked,'start',[])['result'];status,obj=self.call(self.compiler,assembly,1<<20,1<<20)
            self.assertTrue(0<status<=1<<20);self.assertEqual(oracle,41+inc);cases.append((inc,wire,obj,oracle))
        copied=self.folder/'copied';copied.mkdir();target=copied/'compile'
        shutil.copyfile(self.executable,target);target.chmod(0o700);tracer=shutil.which('strace');self.assertIsNotNone(tracer)
        rows=[]
        with patch('json.loads',side_effect=AssertionError('host payload decoder')), \
             patch('hepta.hia_core_workspace_json_native.link_workspace',side_effect=AssertionError('host Core verification bridge')), \
             patch('hepta.hia_core_module_graph_native.link_workspace',side_effect=AssertionError('host materializer')), \
             patch('hepta.hia_agent_assembly.render_assembly',side_effect=AssertionError('host renderer')), \
             patch('hepta.hia_program.verify_program',side_effect=AssertionError('host semantic checker')):
            for inc,wire,wanted,oracle in cases:
                trace=copied/('project-'+str(inc)+'.trace')
                result=subprocess.run([tracer,'-f','-e','trace=execve,openat,clone,fork,vfork','-o',str(trace),str(target)],
                    input=wire,capture_output=True,env={'PATH':''},cwd=copied,timeout=20,preexec_fn=self.native_limits)
                self.assertEqual((result.returncode,result.stdout,result.stderr),(0,wanted,b''))
                text=trace.read_text();self.assertEqual(text.count('execve('),1)
                for forbidden in ('openat(','clone(','fork(','vfork('):self.assertNotIn(forbidden,text)
                entry=b'start';link_frame=struct.pack('<4Q',LINK_MAGIC,1,len(entry),0)+entry+struct.pack('<Q',len(wanted))+wanted
                size,elf=self.call(self.linker,link_frame,65536,LINK_SCRATCH);self.assertTrue(0<size<65536)
                folder=copied/('project-'+str(inc));folder.mkdir()
                payloads={'workspace.json':wire,'program.o':wanted,'linker.input':link_frame,'program.elf':elf}
                for name,data in payloads.items():(folder/name).write_bytes(data)
                executable=folder/'program.elf';executable.chmod(0o700)
                actual=subprocess.run([str(executable)],capture_output=True,env={'PATH':''},cwd=folder,timeout=3)
                self.assertEqual((actual.returncode,actual.stdout,actual.stderr),(oracle,b'',b''))
                rows.append({'increment':inc,'actual_kernel_exit':actual.returncode,'independent_Core_VM_result':oracle,
                    'empty_PATH_one_exec_no_open_or_child':True,'sha256':{n:sha256(v).hexdigest() for n,v in payloads.items()}})
        (self.folder/'actual-projects.json').write_text(json.dumps(rows,indent=2)+'\n')

    def test_semantic_policy_and_feature_refusals_keep_empty_stdout(self):
        cases=[b'',b'null',b'{}',b'\xff',b'{"entry":1,"entry":2}']
        for label in ('undefined','private','duplicate','empty-exports','old-version','nominal','invalid-private'):
            doc=project()
            if label=='undefined':doc['modules'][1]['core']['functions'][0]['blocks'][0]['ops'][1]['args'][0]='undefined_SSA'
            if label=='private':doc['modules'][1]['exports']=[]
            if label=='duplicate':doc['modules'].append(copy.deepcopy(doc['modules'][0]))
            if label=='empty-exports':doc['modules'][0]['exports']=[]
            if label=='old-version':
                for module in doc['modules']:module['core']['schema']='hepta.hia.program.v7'
            if label=='nominal':doc['modules'][0]['core']['types']=[]
            if label=='invalid-private':doc['modules'][1]['core']['functions'].append(f('unused',[],['u32'],[],[b('entry',[],[],ret('undefined'))]))
            cases.append(json.dumps(doc).encode())
        loan=f('start',[],['u32'],['alloc','read','write','trap'],[b('entry',[],[
            c('n','usize',1),i('buffer.new',['n'],[('owner','buffer')]),i('borrow.mut',['owner'],[('view','mutbuf')]),
            i('owner.drop',['owner']),c('zero','u32',0)],ret('zero'))])
        cases.append(json.dumps({'schema':'hepta.hia.core-workspace.v1','entry':'a','modules':[
            {'core':{'schema':'hepta.hia.program.v8','module':'a','functions':[loan]},'exports':['start'],'imports':[]}]}).encode())
        for wire in cases:
            with self.subTest(wire=wire):
                r=self.run_cli(wire);self.assertEqual((r.returncode,r.stdout,r.stderr),(2,b'',b''))

    def test_actual_descriptor_memory_and_EINTR_controls(self):
        wire=json.dumps(project()).encode();wanted=self.run_cli(wire);self.assertEqual(wanted.returncode,0)
        tracer=shutil.which('strace');self.assertIsNotNone(tracer);trace=self.folder/'eintr.trace'
        result=subprocess.run([tracer,'-qq','-o',str(trace),'-e','inject=read:error=EINTR:when=1',
            '-e','inject=write:error=EINTR:when=1',str(self.executable)],input=wire,capture_output=True,env={'PATH':''},timeout=20)
        self.assertEqual((result.returncode,result.stdout,result.stderr),(0,wanted.stdout,b''));self.assertEqual(trace.read_bytes().count(b'(INJECTED)'),2)
        self.assertEqual(self.run_cli(wire,'unexpected').returncode,64)
        r=self.run_cli(b' '*(8<<20)+b'0');self.assertEqual((r.returncode,r.stdout),(3,b''))
        for descriptor in (0,1):
            r=self.run_cli(wire,preexec_fn=lambda fd=descriptor:os.close(fd));self.assertEqual((r.returncode,r.stdout),(4,b''))
        import resource
        def insufficient():resource.setrlimit(resource.RLIMIT_AS,(64<<20,64<<20))
        r=self.run_cli(wire,preexec_fn=insufficient);self.assertEqual((r.returncode,r.stdout),(4,b''))

    def test_actual_128_function_partial_output_and_129_semantic_refusal(self):
        doc=project()
        for n in range(126):doc['modules'][1]['core']['functions'].append(f('unused_'+str(n),[],['u32'],[],[b('entry',[],[c('v','u32',n)],ret('v'))]))
        wire=json.dumps(doc).encode();r=self.run_cli(wire);self.assertEqual(r.returncode,0);wanted=r.stdout;self.assertGreater(len(wanted),4096)
        over=copy.deepcopy(doc);over['modules'][1]['core']['functions'].append(f('one_past',[],['u32'],[],[b('entry',[],[c('v','u32',0)],ret('v'))]))
        r=self.run_cli(json.dumps(over).encode());self.assertEqual((r.returncode,r.stdout),(2,b''))
        import fcntl
        read_fd,write_fd=os.pipe()
        try:
            fcntl.fcntl(write_fd,fcntl.F_SETPIPE_SZ,4096)
            fcntl.fcntl(write_fd,fcntl.F_SETFL,fcntl.fcntl(write_fd,fcntl.F_GETFL)|os.O_NONBLOCK)
            result=subprocess.run([str(self.executable)],input=wire,stdout=write_fd,stderr=subprocess.PIPE,env={'PATH':''},timeout=20)
            os.close(write_fd);write_fd=-1;prefix=b''
            while chunk:=os.read(read_fd,65536):prefix+=chunk
            self.assertEqual((result.returncode,result.stderr),(4,b''));self.assertGreater(len(prefix),0)
            self.assertLess(len(prefix),len(wanted));self.assertEqual(prefix,wanted[:len(prefix)])
        finally:
            os.close(read_fd)
            if write_fd!=-1:os.close(write_fd)

    def test_native_packer_full_four_image_capacity_and_transactional_refusal(self):
        parts=(b'\x01'*(1<<20),b'\x02'*(1<<20),b'\x03'*(1<<20),b'\x04'*(1<<20));wanted=expected_image(*parts);wire=frame(*parts)
        self.assertEqual(self.call(self.packer,wire,BUNDLE_LIMIT,0),(len(wanted),wanted))
        for bad,capacity,status in [(wire,len(wanted)-1,0xfffffffe),(wire+b'x',BUNDLE_LIMIT,0xffffffff),
            (frame(*parts,profile=0),BUNDLE_LIMIT,0xffffffff),
            (frame(parts[0]+b'x',*parts[1:]),BUNDLE_LIMIT,0xffffffff),
            (frame(parts[0],parts[1]+b'x',*parts[2:]),BUNDLE_LIMIT,0xffffffff)]:
            self.assertEqual(self.call(self.packer,bad,capacity,0),(status,b'\xa5'*capacity))


if __name__=='__main__':unittest.main()
