"""Independent Core VM witnesses, actual native stdio and refusal controls."""
from __future__ import annotations

import copy
from hashlib import sha256
import json
import os
import re
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_program_runtime import execute_program
from tools.generate_hia_agent_stdio import (MAGIC, dispatcher_source, packer_source, document,
                                            template, WIRE_LIMIT, LIMIT)
from tools.build_hia_agent_stdio import DISPATCH, PACKER, build

EXPECTED_CAPABILITY = {
    'schema':'hepta.hia.agent-stdio.v1','implementation':'hia-native',
    'operations':['capabilities','verify','compile'],'build_profile':0,
    'input':'primitive-v8-Core-JSON','input_bytes_max':8388608,
    'compiler_bytes_max':1048576,'program_nodes_max':1048576,'json_depth_max':128,
    'target':'linux-x86_64','runtime_python_required':False,
    'edit_and_persistence_implemented':False,'whole_native_delivery_qualified':False,
}
EXPECTED_VERIFIED = b'{"schema":"hepta.hia.agent-stdio.v1","status":"verified","machine_code_published":false}\n'


def cap_bytes(profile=0):
    return (json.dumps({**EXPECTED_CAPABILITY,'build_profile':profile},
                       sort_keys=True,separators=(',',':'))+'\n').encode()


def vm_window(path, payload, *, workspace=b'', capacity=1, start=0, count=1):
    """Hand-written owned-buffer observation; all views/owners are discharged."""
    from tools.hia_selfhost_bulk import Body
    body,owners,views=Body(0),[],[]
    for size,initial,fill in ((len(payload),payload,0),(capacity,b'',165),(len(workspace),workspace,0)):
        owner=body.value('buffer','buffer.new',[body.const('usize',size)])
        view=body.value('mutbuf','borrow.mut',[owner])
        if fill:
            body.effect('buffer.fill',[view,body.const('u8',fill)])
        for index,byte in enumerate(initial):
            if byte:
                body.effect('buffer.store',[view,body.const('usize',index),body.const('u8',byte)])
        owners.append(owner);views.append(view)
    body.effect('loan.end',[views[0]])
    views[0]=body.value('readbuf','borrow.read',[owners[0]])
    result=body.value('u32','call',views,{'function':'f0'})
    values=[body.value('u8','buffer.load',[views[1],body.const('usize',i)])
            for i in range(start,start+count)]
    for view in views:body.effect('loan.end',[view])
    for owner in owners:body.effect('owner.drop',[owner])
    text=('hia-asm.v1 hepta.hia.program.v8 agent_reference\nfn observe() -> (u32'
          +',u8'*count+') effects(alloc,read,write,trap) entry(b0)\nblock b0()\n'
          +body.text()+'  ret('+','.join([result,*values])+')\nend\n'
          +path.read_text().split('\n',1)[1])
    report=execute_program(assemble_program(text),'observe',[],max_steps=4000000)
    assert report['status']=='returned',report
    assert report['resources']['live_owners']==report['resources']['live_local_loans']==0,report
    return report['values'][0],bytes(report['values'][1:])


def dispatcher_reference():
    for profile in range(3):
        workspace=bytearray(48);struct.pack_into('<Q',workspace,40,profile)
        expected=cap_bytes(profile)
        for start in range(0,len(expected)+1,128):
            count=min(128,len(expected)+1-start)
            result,raw=vm_window(DISPATCH,b'capabilities',workspace=workspace,
                                 capacity=len(expected)+1,start=start,count=count)
            assert result==len(expected) and raw==(expected+b'\xa5')[start:start+count],(result,raw)
        for command,mode in [(b'verify',1),(b'compile',2),(b'verifyx',0xffffffff),(b'',0xffffffff)]:
            result,raw=vm_window(DISPATCH,command,workspace=workspace)
            assert result==mode and raw==b'\xa5',(command,result,raw)
        struct.pack_into('<Q',workspace,0,1)
        result,raw=vm_window(DISPATCH,b'verify',workspace=workspace,capacity=len(EXPECTED_VERIFIED)+1,
                             count=len(EXPECTED_VERIFIED)+1)
        assert result==len(EXPECTED_VERIFIED) and raw==EXPECTED_VERIFIED+b'\xa5'
        result,raw=vm_window(DISPATCH,b'compile',workspace=workspace)
        assert result==0xffffffff and raw==b'\xa5'
    workspace=bytes(48)
    result,raw=vm_window(DISPATCH,b'capabilities',workspace=workspace,capacity=3,count=3)
    assert result==0xfffffffe and raw==b'\xa5'*3
    result,raw=vm_window(DISPATCH,b'verify',workspace=bytes(47))
    assert result==0xfffffffd and raw==b'\xa5'


def packed_reference(dispatch=b'\xc3',frontend=b'\xc3',compiler=b'\xc3',profile=0):
    prefix,holes=template()
    raw=bytearray(prefix+dispatch+frontend+compiler)
    struct.pack_into('<QQ',raw,96,len(raw),len(raw))
    for name in ('profile_dispatch_initial','profile_dispatch_verified','profile_frontend'):
        struct.pack_into('<I',raw,holes[name],profile)
    for name,position in [('dispatch_initial',len(prefix)),('dispatch_verified',len(prefix)),
                          ('frontend',len(prefix)+len(dispatch)),
                          ('compiler',len(prefix)+len(dispatch)+len(frontend))]:
        struct.pack_into('<i',raw,holes[name],position-holes[name]-4)
    return bytes(raw)


def packer_reference():
    frame=struct.pack('<5Q',MAGIC,1,1,1,2)+b'\xc3'*3
    expected=packed_reference(profile=2)
    assert expected[:16]==b'\x7fELF\x02\x01\x01'+bytes(9)
    assert struct.unpack_from('<HHIQQ',expected,16)==(2,62,1,0x4000b0,64)
    assert struct.unpack_from('<II',expected,64)==(1,5)
    assert struct.unpack_from('<II',expected,120)==(0x6474e551,6)
    for start in range(0,len(expected)+1,128):
        count=min(128,len(expected)+1-start)
        result,raw=vm_window(PACKER,frame,capacity=len(expected)+1,start=start,count=count)
        assert result==len(expected) and raw==(expected+b'\xa5')[start:start+count],(start,result)
    for source,capacity,status in [(frame[:-1],4,0xffffffff),(frame,4,0xfffffffe),
                                   (struct.pack('<5Q',MAGIC,1,1,1,3)+b'\xc3'*3,4,0xffffffff)]:
        result,raw=vm_window(PACKER,source,capacity=capacity,count=capacity)
        assert result==status and raw==b'\xa5'*capacity


class AgentStdioSourceTests(unittest.TestCase):
    def test_generated_sources_and_dispatcher_vm_before_native_seed(self):
        self.assertEqual(DISPATCH.read_text(),render_assembly(document(dispatcher_source(),'agent_stdio_dispatch')))
        self.assertEqual(PACKER.read_text(),render_assembly(document(packer_source(),'agent_stdio_packer')))
        dispatcher_reference()

    def test_all_packer_bytes_in_core_vm_before_native_seed(self):
        packer_reference()

    def test_unqualified_builder_and_unsupported_profiles_refuse(self):
        with tempfile.TemporaryDirectory(prefix='hia-agent-refusal-') as tmp:
            root=Path(tmp);compiler=root/'compiler';cold=root/'cold.json'
            compiler.write_bytes(b'unqualified');cold.write_text('{}')
            for profile in (True,'unknown'):
                with self.assertRaises(ValueError):build(root/'bad',compiler,cold,output_profile=profile)
            with self.assertRaises(ValueError):build(root/'build',compiler,cold)
            self.assertFalse((root/'build/hia-native').exists())


class AgentStdioNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        dispatcher_reference();packer_reference()  # before this test's B0
        cls.temporary=tempfile.TemporaryDirectory(prefix='hia-agent-native-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root=Path(cls.temporary.name)
        selected=os.environ.get('HEPTA_HIA_AGENT_STDIO_COLD_REPORT')
        if selected:
            cls.cold=Path(selected)
        else:
            from tools.replay_hia_selfhost_cold import cold_replay
            cls.cold=cls.root/'cold.json'
            actual=cold_replay(cls.cold)
            assert actual['status']=='COLD_SELFHOST_REPLAY_PASS',actual
        outer=json.loads(cls.cold.read_bytes())
        assert outer['status']=='COLD_SELFHOST_REPLAY_PASS' and all(outer['checks'].values())
        actual=json.loads(Path(outer['nested_report']).read_bytes())
        cls.compiler=Path(actual['generations'][-1]['produced_image'])
        assert all(h==sha256(cls.compiler.read_bytes()).hexdigest() for h in outer['generation_sha256'])
        cls.executables={profile:build(cls.root/profile,cls.compiler,cls.cold,output_profile=profile)
                         for profile in ('flat','elf','exec')}
        source=DISPATCH.parents[2]/'examples/hia_bootstrap/selfhost.hiaasm'
        cls.sample=assemble_program((source.parent/'bytesum.hiaasm').read_bytes()).as_dict()

    def invoke(self,command,payload=b'',profile='flat',**kwargs):
        return subprocess.run([str(self.executables[profile]),*command],input=payload,
                              capture_output=True,timeout=20,env={'PATH':'','LANG':'C'},**kwargs)

    def test_capabilities_and_usage_need_no_stdin_payload_or_host_tools(self):
        for index,profile in enumerate(('flat','elf','exec')):
            p=self.invoke(['capabilities'],b'not JSON',profile)
            self.assertEqual((p.returncode,p.stderr),(0,b''))
            self.assertEqual(json.loads(p.stdout),{**EXPECTED_CAPABILITY,'build_profile':index})
        for args in ([],['unknown'],['verifyx'],['capabilities','extra'],['x'*32],['']):
            p=self.invoke(args)
            self.assertEqual((p.returncode,p.stdout),(64,b''))
            self.assertEqual(json.loads(p.stderr)['category'],'usage')

    def test_verify_then_compile_actual_hia_program_and_copy(self):
        wire=json.dumps(self.sample,separators=(',',':')).encode()
        checked=self.invoke(['verify'],wire)
        self.assertEqual((checked.returncode,checked.stdout,checked.stderr),(0,EXPECTED_VERIFIED,b''))
        compiled=self.invoke(['compile'],wire)
        self.assertEqual((compiled.returncode,compiled.stderr),(0,b''))
        from tools.qualify_hia_selfhost import compile_stage
        actual,_=compile_stage(self.root,'sample-reference',self.compiler,render_assembly(self.sample).encode())
        self.assertEqual(compiled.stdout,actual.read_bytes())
        from tools.qualify_hia_selfhost import invoke
        receipt,_=invoke(self.root,'sample-execution',actual,b'agent-native',capacity=1,workspace_size=1)
        expected=5381
        for byte in b'agent-native':expected=((expected*33)^byte)&0xffffffff
        self.assertEqual(receipt['core_u32'],expected)
        copied=self.root/'installed-hia-native';shutil.copyfile(self.executables['flat'],copied);copied.chmod(0o700)
        p=subprocess.run([str(copied),'verify'],input=wire,capture_output=True,env={'PATH':''},timeout=20)
        self.assertEqual((p.returncode,p.stdout,p.stderr),(0,EXPECTED_VERIFIED,b''))

    def test_input_representation_semantics_and_ownership_refusals_publish_no_machine_bytes(self):
        malformed=[b'',b'{',b'{"a":1,"a":2}',b'NaN',b'\xff']
        bad=copy.deepcopy(self.sample);bad['functions'][0]['returns']=['bool']
        malformed.append(json.dumps(bad).encode())
        from tests.test_hia_program import b,c,f,i,p,ret
        leaking={'schema':'hepta.hia.program.v8','module':'leak','functions':[
            f('leak',[],['u32'],['alloc','trap'],[b('entry',[],[
                c('n','usize',1),i('buffer.new',['n'],[p('owner','buffer')]),c('ok','u32',0)],ret('ok'))])]}
        malformed.append(json.dumps(leaking).encode())
        for wire in malformed:
            for action in ('verify','compile'):
                with self.subTest(action=action,wire=wire[:30]):
                    result=self.invoke([action],wire)
                    self.assertEqual((result.returncode,result.stdout),(2,b''))
                    self.assertEqual(json.loads(result.stderr)['category'],'input_or_semantic')

    def test_exact_wire_capacity_and_plus_one(self):
        wire=json.dumps(self.sample,separators=(',',':')).encode()
        for count,status in ((WIRE_LIMIT,0),(WIRE_LIMIT+1,3)):
            result=self.invoke(['verify'],wire+b' '*(count-len(wire)))
            self.assertEqual(result.returncode,status,(result.stdout,result.stderr))
            if status:self.assertEqual(result.stdout,b'')

    def test_profile_selection_and_real_generated_executable(self):
        from tools.qualify_hia_selfhost_cli import independent_reference
        reference=independent_reference()
        source=reference['echo_source'].encode().replace(b'v8 selfhost\n',b'v8 selfhost_exec\n',1)
        program=assemble_program(source).as_dict()
        wire=json.dumps(program).encode()
        result=self.invoke(['compile'],wire,profile='exec')
        self.assertEqual((result.returncode,result.stderr),(0,b''))
        executable=self.root/'native-agent-generated-echo'
        executable.write_bytes(result.stdout);executable.chmod(0o700)
        for row in reference['echo']:
            actual=subprocess.run([str(executable)],input=bytes.fromhex(row['input_hex']),
                                  capture_output=True,timeout=20,env={'PATH':''})
            self.assertEqual((actual.returncode,actual.stdout,actual.stderr),
                             (0,bytes.fromhex(row['output_hex']),b''))
        for profile in ('flat','elf'):
            result=self.invoke(['compile'],wire,profile=profile)
            self.assertEqual((result.returncode,result.stdout),(2,b''))
        value={**self.sample,'module':'selfhost_elf'}
        wire=json.dumps(value).encode()
        result=self.invoke(['compile'],wire,profile='elf')
        self.assertEqual((result.returncode,result.stderr),(0,b''))
        self.assertEqual(result.stdout[:4],b'\x7fELF')
        self.assertEqual(struct.unpack_from('<H',result.stdout,16)[0],1)  # ET_REL, not exec
        self.assertEqual(self.invoke(['compile'],wire).returncode,2)

    def test_original_modified_compiler_chains_are_genuine_and_separate(self):
        from tools.qualify_hia_selfhost import compile_stage,mutate_compiler
        original=(DISPATCH.parent/'selfhost.hiaasm').read_bytes()
        for index,source in enumerate((original,mutate_compiler(original))):
            wire=json.dumps(assemble_program(source).as_dict(),separators=(',',':')).encode()
            p=self.invoke(['compile'],wire)
            self.assertEqual((p.returncode,p.stderr),(0,b''))
            expected,_=compile_stage(self.root,'agent-compiler-reference-'+str(index),self.compiler,source)
            self.assertEqual(p.stdout,expected.read_bytes())
            previous=self.root/('agent-compiler-'+str(index)+'.bin');previous.write_bytes(p.stdout)
            b1,_=compile_stage(self.root,'agent-next-1-'+str(index),previous,source)
            b2,_=compile_stage(self.root,'agent-next-2-'+str(index),b1,source)
            self.assertEqual(b1.read_bytes(),b2.read_bytes())
            if index:self.assertNotEqual(b2.read_bytes(),self.compiler.read_bytes())
            else:self.assertEqual(b2.read_bytes(),self.compiler.read_bytes())

    def test_trace_and_real_interrupted_reads_and_writes(self):
        wire=json.dumps(self.sample).encode()
        for interrupted in (False,True):
            trace=self.root/('agent-io-'+str(interrupted)+'.strace')
            options=(['-e','inject=read:error=EINTR:when=1',
                      '-e','inject=write:error=EINTR:when=1'] if interrupted else [])
            p=subprocess.run(['/usr/bin/strace','-qq','-o',str(trace),*options,
                              str(self.executables['flat']),'verify'],input=wire,capture_output=True,timeout=20,
                             env={'PATH':''})
            self.assertEqual((p.returncode,p.stdout,p.stderr),(0,EXPECTED_VERIFIED,b''))
            calls=re.findall(r'^([a-z0-9_]+)\(',trace.read_text(),re.MULTILINE)
            self.assertEqual(set(calls),{'execve','mmap','read','write','exit'})
            self.assertEqual(calls.count('execve'),1)
            if interrupted:self.assertEqual(trace.read_text().count('(INJECTED)'),2)

    def test_actual_descriptor_and_mapping_errors_have_structured_categories(self):
        import resource
        wire=json.dumps(self.sample).encode()
        for mode in ('closed-stdin','full-stdout','mmap-failure'):
            def prepare():
                resource.setrlimit(resource.RLIMIT_CORE,(0,0))
                if mode=='closed-stdin':os.close(0)
                if mode=='full-stdout':
                    descriptor=os.open('/dev/full',os.O_WRONLY)
                    os.dup2(descriptor,1);os.close(descriptor)
                if mode=='mmap-failure':resource.setrlimit(resource.RLIMIT_AS,(2<<20,2<<20))
            # Do not relax the old compiler harness's exact no-argument guard.
            result=self.invoke(['verify'],wire,preexec_fn=prepare)
            self.assertEqual((result.returncode,result.stdout),(4,b''),(mode,result.stderr))
            self.assertEqual(json.loads(result.stderr)['category'],'io_or_mapping')

    def test_real_partial_stdout_is_prefix_then_io_failure_not_publication(self):
        import fcntl
        original=(DISPATCH.parent/'selfhost.hiaasm').read_bytes()
        wire=json.dumps(assemble_program(original).as_dict(),separators=(',',':')).encode()
        read_fd,write_fd=os.pipe()
        try:
            fcntl.fcntl(write_fd,fcntl.F_SETFL,fcntl.fcntl(write_fd,fcntl.F_GETFL)|os.O_NONBLOCK)
            result=subprocess.run([str(self.executables['flat']),'compile'],input=wire,
                                  stdout=write_fd,stderr=subprocess.PIPE,timeout=20,env={'PATH':''})
            os.close(write_fd);write_fd=-1
            parts=[]
            while True:
                part=os.read(read_fd,65536)
                if not part:break
                parts.append(part)
            prefix=b''.join(parts)
            self.assertEqual(result.returncode,4,result.stderr)
            self.assertEqual(json.loads(result.stderr)['category'],'io_or_mapping')
            self.assertTrue(0<len(prefix)<len(self.compiler.read_bytes()))
            self.assertEqual(prefix,self.compiler.read_bytes()[:len(prefix)])
        finally:
            os.close(read_fd)
            if write_fd!=-1:os.close(write_fd)


if __name__=='__main__':
    unittest.main()
