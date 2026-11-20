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
    'operations':['capabilities','verify','compile','render-assembly','assemble','check-assembly','catalog'],'build_profile':0,
    'input':'primitive-v6/v7/v8/v9-Core-JSON','input_bytes_max':8388608,
    'assembly_input':'hia-asm.v1','assembly_input_bytes_max':1048576,
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
        for command,mode in [(b'verify',1),(b'compile',2),(b'render-assembly',3),(b'assemble',4),
                             (b'render-assembla',0xffffffff),(b'render-assembl',0xffffffff),
                             (b'render-assemblyx',0xffffffff),(b'verifyx',0xffffffff),
                             (b'assemblex',0xffffffff),(b'check-assembly',5),
                             (b'check-assembl',0xffffffff),(b'check-assemblx',0xffffffff),
                             (b'check-assemblyx',0xffffffff),(b'',0xffffffff)]:
            result,raw=vm_window(DISPATCH,command,workspace=workspace)
            assert result==mode and raw==b'\xa5',(command,result,raw)
        struct.pack_into('<Q',workspace,0,1)
        result,raw=vm_window(DISPATCH,b'verify',workspace=workspace,capacity=len(EXPECTED_VERIFIED)+1,
                             count=len(EXPECTED_VERIFIED)+1)
        assert result==len(EXPECTED_VERIFIED) and raw==EXPECTED_VERIFIED+b'\xa5'
        result,raw=vm_window(DISPATCH,b'check-assembly',workspace=workspace,capacity=len(EXPECTED_VERIFIED)+1,
                             count=len(EXPECTED_VERIFIED)+1)
        assert result==len(EXPECTED_VERIFIED) and raw==EXPECTED_VERIFIED+b'\xa5'
        result,raw=vm_window(DISPATCH,b'check-assembly',workspace=workspace,
                             capacity=len(EXPECTED_VERIFIED)-1,count=len(EXPECTED_VERIFIED)-1)
        assert result==0xfffffffe and raw==b'\xa5'*(len(EXPECTED_VERIFIED)-1)
        for command in (b'compile',b'render-assembly',b'assemble'):
            result,raw=vm_window(DISPATCH,command,workspace=workspace)
            assert result==0xffffffff and raw==b'\xa5'
        # Hand-built headers independently observe only the output-profile
        # policy, never general machine-code or semantic validity.
        struct.pack_into('<Q',workspace,0,2)
        for selected in range(3):
            artifact=bytearray(b'\x55\x48\x89\xe5') if selected==0 else bytearray(64)
            if selected:
                artifact[:7]=b'\x7fELF\x02\x01\x01'
                struct.pack_into('<HH',artifact,16,selected,62)
            result,raw=vm_window(DISPATCH,artifact,workspace=workspace)
            assert result==(1 if selected==profile else 0xffffffff) and raw==b'\xa5'
        for artifact in (b'',b'\x7fELF',b'\x7fELF'+bytes(60)):
            result,raw=vm_window(DISPATCH,artifact,workspace=workspace)
            assert result==0xffffffff and raw==b'\xa5'
    workspace=bytes(48)
    result,raw=vm_window(DISPATCH,b'capabilities',workspace=workspace,capacity=3,count=3)
    assert result==0xfffffffe and raw==b'\xa5'*3
    result,raw=vm_window(DISPATCH,b'verify',workspace=bytes(47))
    assert result==0xfffffffd and raw==b'\xa5'
    for phase,profile in ((3,0),(0,4),(2,3),(5,0)):
        workspace=bytearray(48)
        struct.pack_into('<Q',workspace,0,phase);struct.pack_into('<Q',workspace,40,profile)
        result,raw=vm_window(DISPATCH,b'assemble',workspace=workspace)
        assert result==0xfffffffd and raw==b'\xa5'
    workspace=struct.pack('<6Q',5,0,0,0,0,3)
    for argument, expected in ((b'--output-profile=flat',1), (b'--output-profile=elf',2),
                               (b'--output-profile=exec',3), (b'--output-profile=elfx',0),
                               (b'--output-profile=',0), (b'--Output-profile=elf',0)):
        result,raw=vm_window(DISPATCH,argument,workspace=workspace)
        assert result==expected and raw==b'\xa5'
    workspace=struct.pack('<6Q',6,0,0,0,0,3)
    for argument, expected in ((b'--input-file',1), (b'--input-filex',0xffffffff),
                               (b'--input-fil',0xffffffff), (b'',0xffffffff)):
        result,raw=vm_window(DISPATCH,argument,workspace=workspace)
        assert result==expected and raw==b'\xa5'


def packed_reference(dispatch=b'\xc3',frontend=b'\xc3',compiler=b'\xc3',profile=0,catalog=b'table'):
    prefix,holes=template()
    raw=bytearray(prefix+dispatch+frontend+compiler+catalog)
    struct.pack_into('<QQ',raw,96,len(raw),len(raw))
    for name in ('profile_dispatch_initial','profile_dispatch_verified','profile_dispatch_output_profile',
                 'profile_dispatch_file_argument',
                 'profile_dispatch_catalog_argument','profile_dispatch_catalog_finish'):
        struct.pack_into('<I',raw,holes[name],profile)
    for name,position in [('dispatch_initial',len(prefix)),('dispatch_verified',len(prefix)),
                          ('dispatch_assembly',len(prefix)),('dispatch_output_profile',len(prefix)),
                          ('dispatch_file_argument',len(prefix)),
                          ('dispatch_catalog_argument',len(prefix)),
                          ('dispatch_catalog_finish',len(prefix)),
                          ('frontend',len(prefix)+len(dispatch)),
                          ('compiler',len(prefix)+len(dispatch)+len(frontend)),
                          ('catalog_data',len(raw)-len(catalog))]:
        struct.pack_into('<i',raw,holes[name],position-holes[name]-4)
    struct.pack_into('<I',raw,holes['catalog_size'],len(catalog))
    return bytes(raw)


def packer_reference():
    frame=struct.pack('<6Q',MAGIC,1,1,1,2,5)+b'\xc3'*3+b'table'
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
                                   (struct.pack('<6Q',MAGIC,1,1,1,4,5)+frame[48:],4,0xffffffff),
                                   (struct.pack('<6Q',MAGIC,1,1,1,2,0)+frame[48:51],4,0xffffffff)]:
        result,raw=vm_window(PACKER,source,capacity=capacity,count=capacity)
        assert result==status and raw==b'\xa5'*capacity


class AgentStdioSourceTests(unittest.TestCase):
    def test_generated_sources_and_dispatcher_vm_before_native_seed(self):
        self.assertEqual(DISPATCH.read_text(),render_assembly(document(dispatcher_source(),'agent_stdio_dispatch')))
        self.assertEqual(PACKER.read_text(),render_assembly(document(packer_source(),'agent_stdio_packer')))
        dispatcher_reference()

    def test_all_packer_bytes_in_core_vm_before_native_seed(self):
        packer_reference()

    def test_catalog_short_output_and_invalid_table_do_not_publish(self):
        workspace=struct.pack('<10Q',4,0,0,0,0,0,0,0,1,1)
        # The synthetic v1 reply lives in the current v1–v9 table format.
        header_size = 4 + 12 * 9
        header = struct.pack('<4I', header_size + 8, 0, 1, 3) + bytes(header_size - 16)
        for table,capacity,status in (
            (header+struct.pack('<2I',0,3)+b'abc',4,3),
            (header+struct.pack('<2I',0,3)+b'abc',2,0xfffffffe),
            (header+struct.pack('<2I',1,3)+b'abc',4,0xffffffff),
        ):
            result,raw=vm_window(DISPATCH,table,workspace=workspace,capacity=capacity,count=capacity)
            self.assertEqual(result,status)
            self.assertEqual(raw,b'abc\xa5' if result==3 else b'\xa5'*capacity)

    def test_unqualified_builder_and_unsupported_profiles_refuse(self):
        with tempfile.TemporaryDirectory(prefix='hia-agent-refusal-') as tmp:
            root=Path(tmp);compiler=root/'compiler';cold=root/'cold.json'
            compiler.write_bytes(b'unqualified');cold.write_text('{}')
            for profile in (True,'unknown'):
                with self.assertRaises(ValueError):build(root/'bad',compiler,cold,output_profile=profile)
            self.assertFalse((root/'bad').exists())
            with self.assertRaises(ValueError):build(root/'build',compiler,cold)
            self.assertFalse((root/'build').exists())


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
                         for profile in ('flat','elf','exec','portable')}
        source=DISPATCH.parents[2]/'examples/hia_bootstrap/selfhost.hepta'
        cls.assembly=(source.parent/'bytesum.hepta').read_bytes()
        cls.sample=assemble_program(cls.assembly).as_dict()

    def invoke(self,command,payload=b'',profile='flat',**kwargs):
        return subprocess.run([str(self.executables[profile]),*command],input=payload,
                              capture_output=True,timeout=20,env={'PATH':'','LANG':'C'},**kwargs)

    def test_capabilities_and_usage_need_no_stdin_payload_or_host_tools(self):
        for index,profile in enumerate(('flat','elf','exec','portable')):
            p=self.invoke(['capabilities'],b'not JSON',profile)
            self.assertEqual((p.returncode,p.stderr),(0,b''))
            self.assertEqual(json.loads(p.stdout),{**EXPECTED_CAPABILITY,'build_profile':index})
        for args in ([],['unknown'],['verifyx'],['render-assembla'],['render-assembl'],
                     ['render-assemblyx'],['assemblex'],['check-assembl'],['check-assemblx'],
                     ['check-assemblyx'],['check-assembly','extra'],['capabilities','extra'],['x'*32],['']):
            p=self.invoke(args)
            self.assertEqual((p.returncode,p.stdout),(64,b''))
            self.assertEqual(json.loads(p.stderr)['category'],'usage')

    def test_catalog_matches_all_hosted_versions_under_empty_path(self):
        from hepta.hia_opcodes import opcode_catalog

        def expected(version):
            schema=f'hepta.hia.program.v{version}'
            return (json.dumps(opcode_catalog(schema),ensure_ascii=False,indent=2,sort_keys=True)+'\n').encode()

        for version in range(1,9):
            with self.subTest(version=version):
                p=self.invoke(['catalog','--schema',f'hepta.hia.program.v{version}'],b'ignored')
                self.assertEqual((p.returncode,p.stdout,p.stderr),(0,expected(version),b''))
        for profile in ('elf','exec'):
            p=self.invoke(['catalog'],profile=profile)
            self.assertEqual((p.returncode,p.stdout,p.stderr),(0,expected(8),b''))
        p=self.invoke(['catalog','--s=hepta.hia.program.v2','--schem','hepta.hia.program.v5'])
        self.assertEqual((p.returncode,p.stdout,p.stderr),(0,expected(5),b''))
        for extra in (['--schema'],['--schema='],['schema'],['--schema-extra'],
                      ['--schema','hepta.hia.program.v9'],['--schema','hepta.hia.program.v80'],
                      ['--schema=hepta.hia.program.v0','--schema=hepta.hia.program.v8'],['x'*64]):
            with self.subTest(extra=extra):
                p=self.invoke(['catalog',*extra])
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
        assembled=self.invoke(['assemble'],self.assembly)
        self.assertEqual((assembled.returncode,assembled.stdout,assembled.stderr),(0,compiled.stdout,b''))
        from tools.qualify_hia_selfhost import invoke
        receipt,_=invoke(self.root,'sample-execution',actual,b'agent-native',capacity=1,workspace_size=1)
        expected=5381
        for byte in b'agent-native':expected=((expected*33)^byte)&0xffffffff
        self.assertEqual(receipt['core_u32'],expected)
        copied=self.root/'installed-hia-native';shutil.copyfile(self.executables['flat'],copied);copied.chmod(0o700)
        p=subprocess.run([str(copied),'verify'],input=wire,capture_output=True,env={'PATH':''},timeout=20)
        self.assertEqual((p.returncode,p.stdout,p.stderr),(0,EXPECTED_VERIFIED,b''))
        p=subprocess.run([str(copied),'assemble'],input=self.assembly,capture_output=True,env={'PATH':''},timeout=20)
        self.assertEqual((p.returncode,p.stdout,p.stderr),(0,compiled.stdout,b''))

    def test_render_assembly_checks_native_semantics_and_survives_copied_empty_PATH(self):
        from unittest.mock import patch
        variants=[]
        for increment in (1,7):
            from tests.test_hia_program import b,c,f,ret
            params=[('s','readbuf'),('o','mutbuf'),('w','mutbuf')]
            doc={'schema':'hepta.hia.program.v8','module':'agent_render','functions':[
                f('answer',params,['u32'],[],[b('entry',copy.deepcopy(params),[c('v','u32',41+increment)],ret('v'))])]}
            variants.append((doc,render_assembly(doc).encode()))
        variants.append((self.sample,render_assembly(self.sample).encode()))
        copied=self.root/'copied-native-render';shutil.copyfile(self.executables['flat'],copied);copied.chmod(0o700)
        trace=self.root/'native-render.trace'
        with patch('json.loads',side_effect=AssertionError('host JSON payload decoder')), \
             patch('hepta.hia_program.verify_program',side_effect=AssertionError('host Core checker')), \
             patch('hepta.hia_agent_assembly.render_assembly',side_effect=AssertionError('host renderer')):
            for doc,wanted in variants:
                wire=json.dumps(doc).encode()
                result=subprocess.run(['/usr/bin/strace','-f','-e','trace=execve,openat,clone,fork,vfork',
                    '-o',str(trace),str(copied),'render-assembly'],input=wire,capture_output=True,
                    env={'PATH':''},timeout=20)
                self.assertEqual((result.returncode,result.stdout,result.stderr),(0,wanted,b''))
                text=trace.read_text();self.assertEqual(text.count('execve('),1)
                for forbidden in ('openat(','clone(','fork(','vfork('):self.assertNotIn(forbidden,text)
        # Unsupported old/nominal/private-invalid programs cannot obtain an
        # apparently successful assembly view before mandatory native checking.
        for label in ('old','nominal','invalid-unused'):
            bad=copy.deepcopy(self.sample)
            if label=='old':bad['schema']='hepta.hia.program.v5'
            elif label=='nominal':bad['types']=[]
            else:bad['functions'].append(f('unused',[],['u32'],[],[b('entry',[],[],ret('undefined'))]))
            result=self.invoke(['render-assembly'],json.dumps(bad).encode())
            self.assertEqual((result.returncode,result.stdout),(2,b''),label)
        # A real interrupted write may not lose the start of the assembly.
        wire=json.dumps(self.sample).encode();wanted=render_assembly(self.sample).encode()
        result=subprocess.run(['/usr/bin/strace','-qq','-o',str(trace),
            '-e','inject=read:error=EINTR:when=1','-e','inject=write:error=EINTR:when=1',
            str(copied),'render-assembly'],input=wire,capture_output=True,env={'PATH':''},timeout=20)
        self.assertEqual((result.returncode,result.stdout,result.stderr),(0,wanted,b''))
        self.assertEqual(trace.read_text().count('(INJECTED)'),2)

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
            for action in ('verify','compile','render-assembly'):
                with self.subTest(action=action,wire=wire[:30]):
                    result=self.invoke([action],wire)
                    self.assertEqual((result.returncode,result.stdout),(2,b''))
                    self.assertEqual(json.loads(result.stderr)['category'],'input_or_semantic')

    def test_exact_wire_capacity_and_plus_one(self):
        wire=json.dumps(self.sample,separators=(',',':')).encode()
        for action in ('verify','render-assembly'):
            for count,status in ((WIRE_LIMIT,0),(WIRE_LIMIT+1,3)):
                result=self.invoke([action],wire+b' '*(count-len(wire)))
                self.assertEqual(result.returncode,status,(action,result.stdout,result.stderr))
                if status:self.assertEqual(result.stdout,b'')

    def test_assembly_wire_capacity_and_exact_source_preservation(self):
        expected=self.invoke(['assemble'],self.assembly)
        self.assertEqual((expected.returncode,expected.stderr),(0,b''))
        for count,status in ((LIMIT,0),(LIMIT+1,3),(WIRE_LIMIT,3)):
            result=self.invoke(['assemble'],self.assembly+b' '*(count-len(self.assembly)))
            self.assertEqual(result.returncode,status,(result.stdout,result.stderr))
            if status:
                self.assertEqual(result.stdout,b'')
                self.assertEqual(json.loads(result.stderr)['category'],'capacity')
            else:self.assertEqual((result.stdout,result.stderr),(expected.stdout,b''))

    def test_check_assembly_has_full_native_semantic_admission_and_no_code_publication(self):
        from unittest.mock import patch
        copied=self.root/'installed-native-check-assembly'
        shutil.copyfile(self.executables['flat'],copied);copied.chmod(0o700)
        with patch('hepta.hia_program.verify_program',side_effect=AssertionError('host Core checker')), \
             patch('hepta.hia_agent_assembly.assemble_program',side_effect=AssertionError('host assembly parser')):
            accepted=subprocess.run([str(copied),'check-assembly'],input=self.assembly,capture_output=True,
                env={'PATH':''},timeout=20)
            self.assertEqual((accepted.returncode,accepted.stdout,accepted.stderr),(0,EXPECTED_VERIFIED,b''))
        for count,status in ((LIMIT,0),(LIMIT+1,3)):
            result=self.invoke(['check-assembly'],self.assembly+b' '*(count-len(self.assembly)))
            self.assertEqual((result.returncode,result.stdout),
                             (status,EXPECTED_VERIFIED if not status else b''))
        object_source=self.assembly.replace(b'v8 selfhost\n',b'v8 selfhost_elf\n',1)
        for profile,source in (('flat',self.assembly),('elf',object_source)):
            result=self.invoke(['check-assembly'],source,profile=profile)
            self.assertEqual((result.returncode,result.stdout,result.stderr),(0,EXPECTED_VERIFIED,b''))
        for profile,source in (('flat',object_source),('elf',self.assembly),('exec',self.assembly)):
            result=self.invoke(['check-assembly'],source,profile=profile)
            self.assertEqual((result.returncode,result.stdout),(2,b''))
            self.assertEqual(json.loads(result.stderr)['category'],'input_or_semantic')

    def test_assembly_syntax_effect_loan_and_owner_refusals(self):
        header=('hia-asm.v1 hepta.hia.program.v8 selfhost_elf\n'
                'fn f0(v0:readbuf,v1:mutbuf,v2:mutbuf) -> (u32) '
                'effects(alloc,read,write,trap) entry(b0)\n'
                'block b0(v0:readbuf,v1:mutbuf,v2:mutbuf)\n')
        ending='  v9:u32 = const() {"value":0}\n  ret(v9)\nend\n'
        negatives=[b'',b'not-hia',b'\xff',json.dumps(self.sample).encode(),
            self.assembly.replace(b'effects(read,write,trap)',b'effects()',1),
            (header+'  v3:readbuf = borrow.read(v0)\n'+ending).encode(),
            (header+'  v3:mutbuf = borrow.mut(v0)\n'+ending).encode(),
            (header+'  v3:usize = const() {"value":1}\n'
             '  v4:buffer = buffer.new(v3)\n'+ending).encode()]
        for source in negatives:
            with self.subTest(source=source[:100]):
                with self.assertRaises(ValueError):assemble_program(source)
                for profile in ('flat','elf','exec'):
                    for action in ('assemble','check-assembly'):
                        result=self.invoke([action],source,profile=profile)
                        self.assertEqual((result.returncode,result.stdout),(2,b''))
                        self.assertEqual(json.loads(result.stderr)['category'],'input_or_semantic')
        for action in ('verify','compile','render-assembly'):
            refused=self.invoke([action],self.assembly)
            self.assertEqual((refused.returncode,refused.stdout),(2,b''))

    def test_profile_selection_and_real_generated_executable(self):
        from tools.qualify_hia_selfhost_cli import independent_reference
        reference=independent_reference()
        source=reference['echo_source'].encode().replace(b'v8 selfhost\n',b'v8 selfhost_exec\n',1)
        program=assemble_program(source).as_dict()
        wire=json.dumps(program).encode()
        result=self.invoke(['compile'],wire,profile='exec')
        self.assertEqual((result.returncode,result.stderr),(0,b''))
        assembled=self.invoke(['assemble'],source,profile='exec')
        self.assertEqual((assembled.returncode,assembled.stdout,assembled.stderr),(0,result.stdout,b''))
        checked=self.invoke(['check-assembly'],source,profile='exec')
        self.assertEqual((checked.returncode,checked.stdout,checked.stderr),(0,EXPECTED_VERIFIED,b''))
        executable=self.root/'native-agent-generated-echo'
        executable.write_bytes(result.stdout);executable.chmod(0o700)
        for row in reference['echo']:
            actual=subprocess.run([str(executable)],input=bytes.fromhex(row['input_hex']),
                                  capture_output=True,timeout=20,env={'PATH':''})
            self.assertEqual((actual.returncode,actual.stdout,actual.stderr),
                             (0,bytes.fromhex(row['output_hex']),b''))
        rendered=self.invoke(['render-assembly'],wire,profile='exec')
        self.assertEqual((rendered.returncode,rendered.stdout,rendered.stderr),(0,render_assembly(program).encode(),b''))
        for profile in ('flat','elf'):
            result=self.invoke(['compile'],wire,profile=profile)
            self.assertEqual((result.returncode,result.stdout),(2,b''))
            rendered=self.invoke(['render-assembly'],wire,profile=profile)
            self.assertEqual((rendered.returncode,rendered.stdout),(2,b''))
            result=self.invoke(['assemble'],source,profile=profile)
            self.assertEqual((result.returncode,result.stdout),(2,b''))
        value={**self.sample,'module':'selfhost_elf'}
        wire=json.dumps(value).encode()
        result=self.invoke(['compile'],wire,profile='elf')
        self.assertEqual((result.returncode,result.stderr),(0,b''))
        self.assertEqual(result.stdout[:4],b'\x7fELF')
        self.assertEqual(struct.unpack_from('<H',result.stdout,16)[0],1)  # ET_REL, not exec
        self.assertEqual(self.invoke(['compile'],wire).returncode,2)
        rendered=self.invoke(['render-assembly'],wire,profile='elf')
        self.assertEqual((rendered.returncode,rendered.stdout,rendered.stderr),(0,render_assembly(value).encode(),b''))
        self.assertEqual(self.invoke(['render-assembly'],wire).returncode,2)
        object_source=self.assembly.replace(b'v8 selfhost\n',b'v8 selfhost_elf\n',1)
        assembled=self.invoke(['assemble'],object_source,profile='elf')
        self.assertEqual((assembled.returncode,assembled.stdout,assembled.stderr),(0,result.stdout,b''))
        for selected in ('flat','exec'):
            refused=self.invoke(['assemble'],object_source,profile=selected)
            self.assertEqual((refused.returncode,refused.stdout),(2,b''))
        for selected in ('elf','exec'):
            refused=self.invoke(['assemble'],self.assembly,profile=selected)
            self.assertEqual((refused.returncode,refused.stdout),(2,b''))

    def test_assembly_explicit_exports_do_not_switch_build_profile(self):
        source=(b'hia-asm.v1 hepta.hia.program.v8 exported\nexports(value)\n'
                b'fn value() -> (u32) effects() entry(b0)\nblock b0()\n'
                b'  result:u32 = const() {"value":7}\n  ret(result)\nend\n')
        program=assemble_program(source)
        expected=self.invoke(['compile'],program.canonical_bytes,profile='elf')
        actual=self.invoke(['assemble'],source,profile='elf')
        self.assertEqual((actual.returncode,actual.stdout,actual.stderr),(0,expected.stdout,b''))
        checked=self.invoke(['check-assembly'],source,profile='elf')
        self.assertEqual((checked.returncode,checked.stdout,checked.stderr),(0,EXPECTED_VERIFIED,b''))
        self.assertEqual(actual.stdout[:4],b'\x7fELF')
        self.assertEqual(struct.unpack_from('<H',actual.stdout,16)[0],1)
        for profile in ('flat','exec'):
            refused=self.invoke(['assemble'],source,profile=profile)
            self.assertEqual((refused.returncode,refused.stdout),(2,b''))

    def test_portable_compiler_selects_all_three_outputs_without_another_binary(self):
        from tools.qualify_hia_selfhost_cli import echo_source
        sources = {
            'flat': self.assembly,
            'elf': self.assembly.replace(b'v8 selfhost\n', b'v8 selfhost_elf\n', 1),
            'exec': echo_source().replace(b'v8 selfhost\n', b'v8 selfhost_exec\n', 1),
        }
        expected_default = self.invoke(['assemble'], sources['flat'])
        actual_default = self.invoke(['assemble'], sources['flat'], profile='portable')
        self.assertEqual((actual_default.returncode, actual_default.stdout), (0, expected_default.stdout))
        for mode, source in sources.items():
            wire = assemble_program(source).canonical_bytes
            for action, payload in (('assemble', source), ('check-assembly', source),
                                    ('compile', wire), ('verify', wire), ('render-assembly', wire)):
                with self.subTest(mode=mode, action=action):
                    expected = self.invoke([action], payload, profile=mode)
                    actual = self.invoke([action, '--output-profile=' + mode], payload, profile='portable')
                    self.assertEqual((expected.returncode, expected.stderr), (0, b''))
                    self.assertEqual((actual.returncode, actual.stdout, actual.stderr), (0, expected.stdout, b''))
        for arguments in (
            ['assemble', '--output-profile=ELF'],
            ['assemble', '--output-profile=elf', '--output-profile=exec'],
            ['assemble', '--output-profile', 'flat'],
            ['capabilities', '--output-profile=elf'],
            ['catalog', '--output-profile=elf'],
        ):
            refused = self.invoke(arguments, sources['flat'], profile='portable')
            self.assertEqual((refused.returncode, refused.stdout), (64, b''))
        refused = self.invoke(['assemble', '--output-profile=elf'], sources['exec'], profile='portable')
        self.assertEqual((refused.returncode, refused.stdout), (2, b''))
        refused = self.invoke(['assemble', '--output-profile=flat'], sources['flat'])
        self.assertEqual((refused.returncode, refused.stdout), (64, b''))

    def test_portable_compiler_reads_ordinary_files_with_the_unchanged_stdio_limits(self):
        folder = self.root / 'input-files'
        folder.mkdir()
        assembly = folder / '编译 sample.hepta'
        assembly.write_bytes(self.assembly)
        core = folder / 'program.json'
        core.write_bytes(assemble_program(self.assembly).canonical_bytes)
        for action, path in (('assemble', assembly), ('check-assembly', assembly),
                             ('compile', core), ('verify', core), ('render-assembly', core)):
            with self.subTest(action=action):
                expected = self.invoke([action], path.read_bytes(), profile='portable')
                observed = self.invoke([action, '--input-file', str(path)], b'not the file', profile='portable')
                self.assertEqual(expected.returncode, 0)
                self.assertEqual((observed.returncode, observed.stdout, observed.stderr),
                                 (0, expected.stdout, b''))
        elf = folder / 'exported.hepta'
        elf.write_bytes(self.assembly.replace(b'v8 selfhost\n', b'v8 selfhost_elf\n', 1))
        flags = ['--output-profile=elf']
        expected = self.invoke(['assemble', *flags], elf.read_bytes(), profile='portable')
        observed = subprocess.run([self.executables['portable'], 'assemble', *flags, '--input-file', elf],
                                  capture_output=True, env={'PATH': ''}, timeout=20,
                                  preexec_fn=lambda: os.close(0))
        self.assertEqual((observed.returncode, observed.stdout, observed.stderr), (0, expected.stdout, b''))
        fifo = folder / 'fifo'
        os.mkfifo(fifo)
        symlink = folder / 'symlink'
        symlink.symlink_to(assembly)
        for path in (fifo, symlink, folder, folder / 'missing'):
            observed = self.invoke(['assemble', '--input-file', path], profile='portable')
            self.assertEqual((observed.returncode, observed.stdout), (4, b''))
        for action, path, ceiling in (('assemble', assembly, 1 << 20), ('verify', core, 8 << 20)):
            raw = path.read_bytes()
            path.write_bytes(raw.ljust(ceiling, b' '))
            result = self.invoke([action, '--input-file', path], profile='portable')
            expected = self.invoke([action], path.read_bytes(), profile='portable')
            self.assertEqual((result.returncode, result.stdout, result.stderr),
                             (expected.returncode, expected.stdout, expected.stderr))
            with path.open('ab') as stream:
                stream.write(b' ')
            result = self.invoke([action, '--input-file', path], profile='portable')
            self.assertEqual((result.returncode, result.stdout), (3, b''))
        for arguments in (['assemble', '--input-file'], ['assemble', '--input-file', ''],
                          ['assemble', '--input-filex', assembly], ['capabilities', '--input-file', assembly],
                          ['assemble', '--input-file', assembly, '--output-profile=elf']):
            result = self.invoke(arguments, profile='portable')
            self.assertEqual((result.returncode, result.stdout), (64, b''))
        result = self.invoke(['assemble', '--input-file', assembly], profile='flat')
        self.assertEqual((result.returncode, result.stdout), (64, b''))

    def test_explicit_v6_v7_schemas_preserve_namespaces_and_feature_guards(self):
        def invoke(action, raw):
            return self.invoke([action, '--output-profile=elf'], raw, profile='portable')

        scalar = (b'hia-asm.v1 hepta.hia.program.v6 signed_export\n'
                  b'exports(entry)\nfn entry(a:i32,b:i32) -> (i32) effects(trap) entry(b0)\n'
                  b'block b0(a:i32,b:i32)\n  n:i32 = int.rem.checked(a,b)\n  ret(n)\nend\n')
        core = assemble_program(scalar)
        assembled = invoke('assemble', scalar)
        compiled = invoke('compile', core.canonical_bytes)
        rendered = invoke('render-assembly', core.canonical_bytes)
        self.assertEqual((assembled.returncode, compiled.returncode, rendered.returncode), (0,0,0))
        self.assertEqual(compiled.stdout, assembled.stdout)
        self.assertEqual(rendered.stdout, render_assembly(core).encode())
        self.assertEqual(struct.unpack_from('<H', assembled.stdout, 16)[0], 1)

        chain = (b'hia-asm.v1 hepta.hia.program.v7 chain_entry\n'
                 b'exports(entry)\nfn entry() -> (u64) effects(alloc) entry(b0)\n'
                 b'block b0()\n  c:chain = chain.empty()\n  _ = owner.drop(c)\n'
                 b'  n:u64 = const() {"value":37}\n  ret(n)\nend\n')
        valid = assemble_program(chain)
        self.assertEqual(invoke('check-assembly',chain).returncode,0)
        self.assertEqual(invoke('verify',valid.canonical_bytes).returncode,0)
        loan = chain.replace(b'entry(b0)\n',b'entry(b0) return_loans([null])\n',1)
        self.assertEqual(invoke('check-assembly',loan.replace(b'program.v7',b'program.v8',1)).returncode,0)
        for raw in (chain.replace(b'program.v7',b'program.v6',1),
                    chain.replace(b'program.v7',b'program.v5',1), loan):
            result=invoke('assemble',raw)
            self.assertEqual((result.returncode,result.stdout),(2,b''))
        for schema in ('hepta.hia.program.v6','hepta.hia.program.v5'):
            prohibited={**valid.as_dict(),'schema':schema}
            result=invoke('compile',json.dumps(prohibited).encode())
            self.assertEqual((result.returncode,result.stdout),(2,b''))

    def test_original_modified_compiler_chains_are_genuine_and_separate(self):
        from tools.qualify_hia_selfhost import compile_stage,mutate_compiler
        original=(DISPATCH.parent/'selfhost.hepta').read_bytes()
        for index,source in enumerate((original,mutate_compiler(original))):
            wire=json.dumps(assemble_program(source).as_dict(),separators=(',',':')).encode()
            p=self.invoke(['compile'],wire)
            self.assertEqual((p.returncode,p.stderr),(0,b''))
            direct=self.invoke(['assemble'],source)
            self.assertEqual((direct.returncode,direct.stdout,direct.stderr),(0,p.stdout,b''))
            expected,_=compile_stage(self.root,'agent-compiler-reference-'+str(index),self.compiler,source)
            self.assertEqual(p.stdout,expected.read_bytes())
            previous=self.root/('agent-compiler-'+str(index)+'.bin');previous.write_bytes(p.stdout)
            b1,_=compile_stage(self.root,'agent-next-1-'+str(index),previous,source)
            b2,_=compile_stage(self.root,'agent-next-2-'+str(index),b1,source)
            self.assertEqual(b1.read_bytes(),b2.read_bytes())
            if index:self.assertNotEqual(b2.read_bytes(),self.compiler.read_bytes())
            else:self.assertEqual(b2.read_bytes(),self.compiler.read_bytes())

    def test_raw_assembly_produces_original_and_modified_executable_selfhost_chains(self):
        from tools.qualify_hia_selfhost import mutate_compiler, with_selfhost_module
        original=(DISPATCH.parent/'selfhost.hepta').read_bytes()
        fixed_points=[]
        for index,raw in enumerate((original,mutate_compiler(original))):
            source=with_selfhost_module(raw,b'selfhost_exec')
            first=self.invoke(['assemble'],source,profile='exec')
            self.assertEqual((first.returncode,first.stderr),(0,b''))
            images=[first.stdout]
            for generation in (1,2):
                path=self.root/f'assembly-selfhost-{index}-{generation}'
                path.write_bytes(images[-1]);path.chmod(0o700)
                actual=subprocess.run([str(path)],input=source,capture_output=True,
                                      timeout=20,env={'PATH':'','LANG':'C'})
                self.assertEqual((actual.returncode,actual.stderr),(0,b''))
                images.append(actual.stdout)
            self.assertEqual(images[1],images[2])
            if index:self.assertNotEqual(images[0],images[1])
            else:self.assertEqual(images[0],images[1])
            fixed_points.append(images[2])
        self.assertNotEqual(*fixed_points)

    def test_trace_and_real_interrupted_reads_and_writes(self):
        wire=json.dumps(self.sample).encode()
        compiled=self.invoke(['compile'],wire)
        self.assertEqual((compiled.returncode,compiled.stderr),(0,b''))
        for action,payload,expected in (('verify',wire,EXPECTED_VERIFIED),
                                        ('check-assembly',self.assembly,EXPECTED_VERIFIED),
                                        ('assemble',self.assembly,compiled.stdout)):
            for interrupted in (False,True):
                trace=self.root/f'agent-io-{action}-{interrupted}.strace'
                options=(['-e','inject=read:error=EINTR:when=1',
                          '-e','inject=write:error=EINTR:when=1'] if interrupted else [])
                p=subprocess.run(['/usr/bin/strace','-qq','-o',str(trace),*options,
                                  str(self.executables['flat']),action],input=payload,capture_output=True,timeout=20,
                                 env={'PATH':''})
                self.assertEqual((p.returncode,p.stdout,p.stderr),(0,expected,b''))
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
            for action,payload in (('verify',wire),('check-assembly',self.assembly),('assemble',self.assembly)):
                result=self.invoke([action],payload,preexec_fn=prepare)
                self.assertEqual((result.returncode,result.stdout),(4,b''),(mode,action,result.stderr))
                self.assertEqual(json.loads(result.stderr)['category'],'io_or_mapping')

    def test_real_partial_stdout_is_prefix_then_io_failure_not_publication(self):
        import fcntl
        original=(DISPATCH.parent/'selfhost.hepta').read_bytes()
        wire=json.dumps(assemble_program(original).as_dict(),separators=(',',':')).encode()
        for action,payload in (('compile',wire),('assemble',original)):
            read_fd,write_fd=os.pipe()
            try:
                fcntl.fcntl(write_fd,fcntl.F_SETFL,fcntl.fcntl(write_fd,fcntl.F_GETFL)|os.O_NONBLOCK)
                result=subprocess.run([str(self.executables['flat']),action],input=payload,
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
