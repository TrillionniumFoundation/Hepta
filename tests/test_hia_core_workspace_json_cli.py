"""Actual native workspace filter, independent VM packer and installed pipeline.

Native workspace linking is not general Core type/resource admission. That
boundary is tested explicitly, rather than trusting a successful producer.
"""
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import unittest
from unittest.mock import patch

from tests.test_hia_core_workspace_json_native import independent_project, project, wire
from tools.generate_hia_core_workspace_json_cli import (MAGIC, OUTPUT_BYTES,
    ARENA_BYTES, PRIVATE_BYTES, WORKSPACE_BYTES, document)

ROOT = Path(__file__).resolve().parents[1]
PACKER = ROOT/'examples/hia_bootstrap/core_workspace_json_packer.hiaasm'


def vm_pack(raw, capacity=4096):
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program_runtime import _Machine, _Owner, _View
    checked = assemble_program(PACKER.read_bytes())
    machine = _Machine(checked, 2000000, 16 << 20, None, 256)
    owners = [_Owner(-1, bytearray(raw)), _Owner(-2, bytearray(b'Z'*capacity)),
              _Owner(-3, bytearray())]
    fn = next(f for f in checked.as_dict()['functions'] if f['name']=='f0')
    status = machine.invoke(fn, [_View(owners[0],False),_View(owners[1],True),_View(owners[2],True)])[0]
    return status, bytes(owners[1].data[:status]) if status < 0xffff0000 else bytes(owners[1].data)


class CoreWorkspaceJsonCliSourceTests(unittest.TestCase):
    def test_actual_packer_VM_before_seed_and_unchanged_full_transport_sizes(self):
        from hepta.hia_agent_assembly import render_assembly
        from hepta.hia_json_decode_native import arena_sizes
        from hepta.hia_json_preflight_native import scratch_sizes
        from hepta.hia_core_workspace_json_native import PRIVATE_BYTES as kernel_private
        from tools.qualify_hia_selfhost_cli import inspect_executable
        self.assertEqual(PACKER.read_text(), render_assembly(document()))
        self.assertEqual(PRIVATE_BYTES,kernel_private)
        self.assertEqual(ARENA_BYTES,arena_sizes(8 << 20,1 << 20,128)[0])
        self.assertEqual(OUTPUT_BYTES,scratch_sizes(8 << 20,1 << 20,128)[0])
        self.assertEqual(WORKSPACE_BYTES,ARENA_BYTES+PRIVATE_BYTES)
        frame = struct.pack('<QQ',MAGIC,3)+b'\x31\xc0\xc3'
        size,image=vm_pack(frame)
        self.assertEqual(len(image),size)
        self.assertEqual(image[-3:],b'\x31\xc0\xc3')
        self.assertFalse(inspect_executable(image)['dynamic_loader'])
        for raw,capacity,status in [(b'bad',4096,0xffffffff),(frame+b'x',4096,0xffffffff),
                                    (frame,32,0xfffffffe)]:
            self.assertEqual(vm_pack(raw,capacity),(status,b'Z'*capacity))


class CoreWorkspaceJsonCliNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        CoreWorkspaceJsonCliSourceTests('test_actual_packer_VM_before_seed_and_unchanged_full_transport_sizes').test_actual_packer_VM_before_seed_and_unchanged_full_transport_sizes()
        from tests.test_hia_core_workspace_json_native import CoreWorkspaceJsonNativeTests
        CoreWorkspaceJsonNativeTests.setUpClass.__func__(cls)
        from tools.qualify_hia_selfhost import compile_stage,invoke
        packer,cls.packer_receipt=compile_stage(cls.folder,'workspace-json-packer',cls.compiler,PACKER.read_bytes())
        cls.packer=packer
        frame=struct.pack('<QQ',MAGIC,cls.image.stat().st_size)+cls.image.read_bytes()
        receipt,raw=invoke(cls.folder,'workspace-json-pack',packer,frame)
        size=receipt['core_u32'];assert 0<size<1<<20
        cls.executable=cls.folder/'hia-workspace-json'
        cls.executable.write_bytes(raw[:size]);cls.executable.chmod(0o700)
        retained=os.environ.get('HEPTA_HIA_CORE_WORKSPACE_CLI_OBSERVATIONS')
        if retained:
            folder=Path(retained);folder.mkdir(parents=True)
            payloads={'kernel.image.bin':cls.image.read_bytes(),'packer.image.bin':packer.read_bytes(),
                      'hia-workspace-json':cls.executable.read_bytes()}
            for name,data in payloads.items():(folder/name).write_bytes(data)
            (folder/'native-build.json').write_text(json.dumps({'compile_receipt':cls.packer_receipt,
                'pack_receipt':receipt,'sha256':{k:sha256(v).hexdigest() for k,v in payloads.items()}},indent=2)+'\n')

    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()

    def run_cli(self,raw,*args,executable=None):
        return subprocess.run([str(executable or self.executable),*args],input=raw,
            capture_output=True,timeout=20,cwd=self.folder,env={'PATH':'','HOME':'/nonexistent','LANG':'C'})

    def test_original_modified_and_reordered_projects_no_foreign_materializer(self):
        original,expected=independent_project()
        actual=self.run_cli(wire(original))
        self.assertEqual((actual.returncode,actual.stderr),(0,b''))
        self.assertEqual(json.loads(actual.stdout),expected)
        for increment in (1,7):
            for reverse in (False,True):
                p=project(increment)
                if reverse:p['modules'].reverse()
                raw=wire(p);expected=self.native.run(raw)
                with patch('json.loads',side_effect=AssertionError('foreign decoder')), \
                     patch('hepta.hia_core_module_graph_native.link_workspace',side_effect=AssertionError('host linker')):
                    actual=self.run_cli(raw)
                self.assertEqual((actual.returncode,actual.stdout,actual.stderr),(0,expected,b''))

    def test_actual_copied_install_syscalls_have_no_interpreter_loader_or_file_access(self):
        installed=self.folder/'copied-install';installed.mkdir()
        executable=installed/'workspace';executable.write_bytes(self.executable.read_bytes());executable.chmod(0o700)
        raw=wire(project(7));expected=self.native.run(raw)
        tracer=shutil.which('strace');self.assertIsNotNone(tracer)
        trace=self.folder/'workspace-runtime.trace'
        actual=subprocess.run([tracer,'-qq','-f','-o',str(trace),str(executable)],input=raw,
            capture_output=True,timeout=20,cwd=installed,env={'PATH':'','HOME':'/nonexistent'})
        self.assertEqual((actual.returncode,actual.stdout,actual.stderr),(0,expected,b''))
        text=trace.read_text()
        self.assertEqual(text.count('execve('),1)
        for forbidden in ('openat(', 'clone(', 'fork(', 'vfork(', 'mprotect('):
            self.assertNotIn(forbidden,text)
        self.assertEqual(text.count('mmap('),1)

    def test_real_refusals_never_publish_partial_JSON_and_transport_limits_hold(self):
        p=project();p['modules'][1]['exports']=[]
        for raw in (b'',b'{}',wire(project())+b'!',wire(p),
                    b'{"schema":0,"\\u0073chema":1}'):
            actual=self.run_cli(raw)
            self.assertEqual((actual.returncode,actual.stdout,actual.stderr),(2,b'',b''))
        actual=self.run_cli(b' '*(8 << 20)+b'0')
        self.assertEqual((actual.returncode,actual.stdout,actual.stderr),(3,b'',b''))
        actual=self.run_cli(wire(project()),'unexpected')
        self.assertEqual((actual.returncode,actual.stdout,actual.stderr),(64,b'',b''))

    def test_output_is_not_a_general_Core_safety_receipt(self):
        from hepta.hia_program import verify_program,HIAProgramRejected
        p=project();p['modules'][1]['core']['functions'][0]['blocks'][0]['ops'][0]['attrs']['value']=-1
        result=self.run_cli(wire(p))
        self.assertEqual(result.returncode,0)
        with self.assertRaises(HIAProgramRejected):verify_program(result.stdout)

    def test_actual_workspace_to_native_JSON_compiler_to_public_ELF_ABI(self):
        from tools.qualify_hia_selfhost import compile_stage,invoke
        from tools.generate_hia_core_json_cli import MAGIC as compiler_magic
        from hepta.object_symbols import inspect_object_symbols
        frontend,_=compile_stage(self.folder,'pipeline-frontend',self.compiler,
            (ROOT/'examples/hia_bootstrap/core_json_frontend.hiaasm').read_bytes())
        packer,_=compile_stage(self.folder,'pipeline-compiler-packer',self.compiler,
            (ROOT/'examples/hia_bootstrap/core_json_cli_packer.hiaasm').read_bytes())
        frame=struct.pack('<4Q',compiler_magic,frontend.stat().st_size,self.compiler.stat().st_size,1)
        frame+=frontend.read_bytes()+self.compiler.read_bytes()
        receipt,packed=invoke(self.folder,'pipeline-compiler-pack',packer,frame)
        size=receipt['core_u32'];self.assertTrue(0<size<1<<20)
        compiler_cli=self.folder/'hia-core-json';compiler_cli.write_bytes(packed[:size]);compiler_cli.chmod(0o700)
        for increment in (1,7):
            for reverse in (False,True):
                p=project(increment)
                if reverse:p['modules'].reverse()
                source=wire(p)
                with patch('json.loads',side_effect=AssertionError('foreign JSON parser')), \
                     patch('tools.qualify_hia_selfhost.compile_stage',side_effect=AssertionError('host runtime compilation')):
                    linked=self.run_cli(source)
                    built=self.run_cli(linked.stdout,executable=compiler_cli)
                self.assertEqual((linked.returncode,built.returncode,linked.stderr,built.stderr),(0,0,b'',b''))
                inventory=inspect_object_symbols(built.stdout,'ELF64',62)
                self.assertEqual(inventory['defined'],frozenset({'work'}))
                label='pipeline-'+str(increment)+'-'+str(int(reverse))
                obj=self.folder/(label+'.o');obj.write_bytes(built.stdout)
                shared=self.folder/(label+'.so')
                subprocess.run(['cc','-shared','-Wl,-z,defs,-z,noexecstack,-z,relro,-z,now',str(obj),'-o',str(shared)],
                    capture_output=True,check=True,timeout=10)
                loaded=ctypes.CDLL(str(shared));fn=loaded.work
                fn.argtypes=[ctypes.c_uint32];fn.restype=ctypes.c_uint32
                arguments=(0,1,41,255,65535,0xffffffff)
                for value in arguments:self.assertEqual(fn(value),(value+increment)&0xffffffff)
                retained=os.environ.get('HEPTA_HIA_CORE_WORKSPACE_CLI_OBSERVATIONS')
                if retained:
                    folder=Path(retained)/label;folder.mkdir()
                    payloads={'workspace.json':source,'linked-core.json':linked.stdout,'program.o':built.stdout,
                              'library.so':shared.read_bytes(),'hia-core-json':compiler_cli.read_bytes()}
                    for name,data in payloads.items():(folder/name).write_bytes(data)
                    (folder/'execution.json').write_text(json.dumps({'increment':increment,'reverse':reverse,
                        'arguments':arguments,'actual_public_ABI_calls':len(arguments),'empty_PATH':True,
                        'runtime_host_payload_parser_or_compiler':False,'host_shared_linker_used':True,
                        'defined_symbols':sorted(inventory['defined']),
                        'sha256':{k:sha256(v).hexdigest() for k,v in payloads.items()}},indent=2)+'\n')

    def test_actual_EINTR_and_nonblocking_partial_write_do_not_claim_complete_publication(self):
        import fcntl
        from tests.test_hia_program import b,f,i,m,ret
        tracer=shutil.which('strace');self.assertIsNotNone(tracer)
        raw=wire(project());expected=self.native.run(raw)
        trace=self.folder/'workspace-eintr.trace'
        actual=subprocess.run([tracer,'-qq','-o',str(trace),'-e','inject=read:error=EINTR:when=1',
            '-e','inject=write:error=EINTR:when=1',str(self.executable)],input=raw,
            capture_output=True,env={'PATH':''},timeout=20)
        self.assertEqual((actual.returncode,actual.stdout,actual.stderr),(0,expected,b''))
        self.assertEqual(trace.read_bytes().count(b'(INJECTED)'),2)
        app=m(f('main',[],[],[],[b('entry',[],[i('call',[],[],function='use') for _ in range(16384)],ret())]))
        lib=m(f('work',[],[],[],[b('entry',[],[],ret())]))
        app.update(schema='hepta.hia.program.v8',module='app');lib.update(schema='hepta.hia.program.v8',module='lib')
        p={'schema':'hepta.hia.core-workspace.v1','entry':'app','modules':[
            {'core':app,'imports':[{'alias':'use','module':'lib','symbol':'work'}],'exports':['main']},
            {'core':lib,'imports':[],'exports':['work']}]}
        raw=wire(p);expected=self.native.run(raw)
        complete=self.run_cli(raw)
        self.assertEqual((complete.returncode,complete.stdout),(0,expected))
        read_fd,write_fd=os.pipe()
        try:
            fcntl.fcntl(write_fd,fcntl.F_SETPIPE_SZ,4096)
            fcntl.fcntl(write_fd,fcntl.F_SETFL,fcntl.fcntl(write_fd,fcntl.F_GETFL)|os.O_NONBLOCK)
            actual=subprocess.run([str(self.executable)],input=raw,stdout=write_fd,stderr=subprocess.PIPE,
                timeout=20,env={'PATH':''})
            os.close(write_fd);write_fd=-1
            prefix=os.read(read_fd,8192)
            self.assertEqual((actual.returncode,actual.stderr),(4,b''))
            self.assertGreater(len(prefix),0);self.assertLess(len(prefix),len(expected))
            self.assertEqual(prefix,expected[:len(prefix)])
        finally:
            os.close(read_fd)
            if write_fd>=0:os.close(write_fd)

    def test_matching_cold_build_required_and_qualified_installed_copy_when_available(self):
        from tools.build_hia_core_workspace_json_cli import build
        cold=os.environ.get('HEPTA_HIA_CORE_MODULE_GRAPH_COLD_REPORT')
        if not cold:
            invalid=self.folder/'bad-cold.json';invalid.write_text('{}')
            with self.assertRaisesRegex(ValueError,'completed matching'):
                build(self.folder/'refused',self.compiler,invalid)
            self.assertFalse((self.folder/'refused').exists())
            return
        path=build(self.folder/'cold-installed',self.compiler,Path(cold))
        result=self.run_cli(wire(project()),executable=path)
        self.assertEqual((result.returncode,result.stdout,result.stderr),(0,self.native.run(wire(project())),b''))
        report=json.loads((path.parent/'build.json').read_bytes())
        self.assertTrue(report['output_requires_general_Core_verification'])
        self.assertFalse(report['native_general_Core_verifier'])
        self.assertEqual(report['executable_sha256'],sha256(path.read_bytes()).hexdigest())


if __name__=='__main__':unittest.main()
