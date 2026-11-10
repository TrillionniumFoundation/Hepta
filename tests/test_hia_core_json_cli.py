"""Independent packer VM, native two-stage executable and real failure paths."""
from __future__ import annotations
import copy
from hashlib import sha256
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_agent_assembly import assemble_program, render_assembly
from tools.generate_hia_core_json_cli import MAGIC, LIMIT, template, document
from tools.build_hia_core_json_cli import SOURCE, build

ROOT = Path(__file__).resolve().parents[1]


def frame(frontend, compiler, profile=0):
    return struct.pack('<4Q', MAGIC, len(frontend), len(compiler), profile) + frontend + compiler


def expected_image(frontend, compiler, profile=0):
    """Independent byte construction; never used to produce a native artifact."""
    prefix, holes = template()
    data = bytearray(prefix + frontend + compiler)
    struct.pack_into('<QQ', data, 96, len(data), len(data))
    struct.pack_into('<I', data, holes['profile'], profile)
    struct.pack_into('<i', data, holes['frontend'], len(prefix)-holes['frontend']-4)
    struct.pack_into('<i', data, holes['compiler'], len(prefix)+len(frontend)-holes['compiler']-4)
    return bytes(data)


def independent_packer_reference(profile=1):
    from tools.hia_selfhost_bulk import Body
    from hepta.hia_program import execute_program
    source = frame(b'\xc3', b'\xc3', profile)
    expected = expected_image(b'\xc3', b'\xc3', profile)
    # Observe all ELF headers, each dynamically patched word, both copied
    # payload bytes and the first untouched canary, within the VM result bound.
    _, holes = template()
    offsets = list(range(176))
    offsets += [h+j for h in holes.values() for j in range(4)]
    offsets += [len(expected)-2, len(expected)-1, len(expected)]
    body, owners, views = Body(0), [], []
    for size, initial in ((len(source), source), (len(expected)+1,b''), (0,b'')):
        owner = body.value('buffer','buffer.new',[body.const('usize',size)])
        view = body.value('mutbuf','borrow.mut',[owner])
        for i, byte in enumerate(initial):
            if byte: body.effect('buffer.store',[view,body.const('usize',i),body.const('u8',byte)])
        owners.append(owner); views.append(view)
    body.effect('loan.end',[views[0]])
    views[0] = body.value('readbuf','borrow.read',[owners[0]])
    result = body.value('u32','call',views,{'function':'f0'})
    observed = [body.value('u8','buffer.load',[views[1],body.const('usize',i)]) for i in offsets]
    for view in views: body.effect('loan.end',[view])
    for owner in owners: body.effect('owner.drop',[owner])
    wrapper = ('hia-asm.v1 hepta.hia.program.v8 packer_reference\nfn observe() -> (u32,'
        + ','.join(['u8']*len(offsets)) + ') effects(alloc,read,write,trap) entry(b0)\nblock b0()\n'
        + body.text() + '  ret(' + ','.join([result,*observed]) + ')\nend\n'
        + SOURCE.read_text().split('\n',1)[1])
    actual = execute_program(assemble_program(wrapper),'observe',[],max_steps=2000000)
    assert actual['status'] == 'returned', actual
    assert actual['values'] == [len(expected), *[expected[i] if i < len(expected) else 0 for i in offsets]], actual
    assert actual['resources']['live_owners'] == actual['resources']['live_local_loans'] == 0
    return actual


def independent_export_pair():
    """Two source modules retain different, identically named private helpers."""
    from hepta.hia_program import execute_program
    from tools.hia_selfhost_exports_cases import document,allocated_document
    arguments=[250,65000,4000000000,2**64-10,17,-120,-32000,-2000000000,
               -(2**63)+7,-9,True,3,4,5,6,7]
    documents,expected=[],{}
    for prefix,private in (('cli_left_',41),('cli_right_',59)):
        value=document()
        wanted={'private_value','via_private','identity_i8','identity_bool','mixed'}
        value['functions']=[f for f in value['functions'] if f['name'] in wanted]
        value['functions'].extend(allocated_document()['functions'])
        names={f['name']:prefix+f['name'] for f in value['functions'] if f['name']!='private_value'}
        for function in value['functions']:
            if function['name']=='private_value':function['blocks'][0]['ops'][0]['attrs']['value']=private
            function['name']=names.get(function['name'],function['name'])
            for block in function['blocks']:
                for op in block['ops']:
                    if op['op']=='call':op['attrs']['function']=names.get(op['attrs']['function'],op['attrs']['function'])
        value['exports']=list(names.values());value['module']=prefix+'source_module'
        checked=assemble_program(render_assembly(value))
        for name,args in (('mixed',arguments),('via_private',[]),('allocated_size',[37]),
                          ('identity_i8',[-120]),('identity_bool',[True])):
            result=execute_program(checked,prefix+name,args)
            assert result['status']=='returned' and result['resources']['live_owners']==0,result
            expected[prefix+name]=int(result['values'][0])
        documents.append(value)
    return documents,expected


class CoreJsonCliSourceTests(unittest.TestCase):
    def test_generated_packer_and_independent_VM_before_native_seed(self):
        self.assertEqual(SOURCE.read_text(),render_assembly(document()))
        self.assertEqual(len(assemble_program(SOURCE.read_bytes()).as_dict()['functions']),4)
        for profile in (0,1,2):independent_packer_reference(profile)

    def test_incomplete_or_wrong_cold_qualification_cannot_build_executable(self):
        with tempfile.TemporaryDirectory(prefix='hia-json-cli-refusal-') as tmp:
            folder = Path(tmp)
            compiler, cold = folder/'compiler', folder/'cold.json'
            compiler.write_bytes(b'unqualified'); cold.write_text('{}')
            with self.assertRaises(ValueError): build(folder/'build',compiler,cold)
            self.assertFalse((folder/'build/hia-core-json').exists())
            with self.assertRaises(ValueError): build(folder/'bad-profile',compiler,cold,output_profile=True)


class CoreJsonCliNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for profile in (0,1,2):independent_packer_reference(profile)  # BEFORE B0
        from tools.qualify_hia_selfhost import build_seed, compile_stage, mutate_compiler
        cls.original = (ROOT/'examples/hia_bootstrap/selfhost.hiaasm').read_bytes()
        cls.modified = mutate_compiler(cls.original)
        cls.wires = [json.dumps(assemble_program(s).as_dict(),separators=(',',':')).encode()
                     for s in (cls.original,cls.modified)]
        cls.sample = assemble_program((ROOT/'examples/hia_bootstrap/bytesum.hiaasm').read_bytes()).as_dict()
        cls.wire = json.dumps(cls.sample,separators=(',',':')).encode()
        from tools.hia_selfhost_native_observer import independent_reference
        cls.observer_reference = independent_reference()  # every ELF byte BEFORE B0
        cls.export_documents,cls.export_reference=independent_export_pair()
        cls.export_wires=[json.dumps(value,separators=(',',':')).encode() for value in cls.export_documents]
        from tools.qualify_hia_selfhost_cli import independent_reference as cli_reference
        cls.exec_reference = cli_reference()  # unrelated Core echo oracle BEFORE B0
        from tests.test_hia_core_json_frontend_native import vm_export_render
        echo=assemble_program(cls.exec_reference['echo_source']).as_dict()
        echo['module']='selfhost_exec'
        echo_assembly=render_assembly(echo).encode()
        assert vm_export_render(echo,2)==(len(echo_assembly),echo_assembly)
        cls.exec_sources = [s.replace(b'v8 selfhost\n',b'v8 selfhost_exec\n',1)
                            for s in (cls.original,cls.modified)]
        cls.exec_wires = [json.dumps(assemble_program(s).as_dict(),separators=(',',':')).encode()
                          for s in cls.exec_sources]
        cls.temporary = tempfile.TemporaryDirectory(prefix='hia-json-cli-native-')
        cls.folder = Path(cls.temporary.name)
        seed,_ = build_seed(cls.folder)
        first,_ = compile_stage(cls.folder,'B1',seed,cls.original,image_format='seed-shared')
        cls.compiler,_ = compile_stage(cls.folder,'B2',first,cls.original)
        assert first.read_bytes() == cls.compiler.read_bytes()
        cls.frontend,_ = compile_stage(cls.folder,'frontend',cls.compiler,
            (ROOT/'examples/hia_bootstrap/core_json_frontend.hiaasm').read_bytes())
        cls.packer,_ = compile_stage(cls.folder,'packer',cls.compiler,SOURCE.read_bytes())
        from tools.hia_selfhost_native_observer import build as build_observer
        cls.observer, _ = build_observer(cls.folder, cls.compiler, cls.observer_reference)
        cls.executables = []
        for profile in (0,1,2):
            receipt,output = cls.pack(f'pack-{profile}',frame(cls.frontend.read_bytes(),cls.compiler.read_bytes(),profile))
            expected = expected_image(cls.frontend.read_bytes(),cls.compiler.read_bytes(),profile)
            assert receipt['core_u32'] == len(expected) and output[:len(expected)] == expected
            path = cls.folder/f'hia-core-json-{profile}'
            path.write_bytes(output[:len(expected)]); path.chmod(0o700)
            cls.executables.append(path)

    @classmethod
    def tearDownClass(cls): cls.temporary.cleanup()

    @classmethod
    def pack(cls,label,data,capacity=LIMIT):
        from tools.qualify_hia_selfhost import invoke
        return invoke(cls.folder,label,cls.packer,data,capacity=capacity,workspace_size=0)

    def run_cli(self,wire,status=0,profile=0):
        result = subprocess.run([str(self.executables[profile])],input=wire,
            capture_output=True,timeout=15,cwd=self.folder,
            env={'PATH':'/nonexistent','HOME':'/nonexistent','LANG':'C','LC_ALL':'C'})
        self.assertEqual(result.returncode,status,result.stderr)
        self.assertEqual(result.stderr,b'')
        if status: self.assertEqual(result.stdout,b'')
        return result.stdout

    def test_native_packer_exact_layout_and_atomic_frame_refusals(self):
        for i,data in enumerate((b'',bytes(32),frame(b'',b'\xc3'),frame(b'\xc3',b''),
                frame(b'\xc3',b'\xc3',3),frame(b'\xc3',b'\xc3')+b'\0',
                struct.pack('<4Q',MAGIC,2**64-1,1,0)+b'\0')):
            receipt,_ = self.pack(f'bad-frame-{i}',data)
            self.assertEqual(receipt['core_u32'],0xffffffff)
            self.assertTrue(receipt['output_unchanged'])
        receipt,_ = self.pack('short-output',frame(b'\xc3',b'\xc3'),capacity=len(template()[0])+1)
        self.assertEqual(receipt['core_u32'],0xfffffffe)
        self.assertTrue(receipt['output_unchanged'])
        # Neither the packer nor its caller treats these trusted image bytes as
        # sandboxed or semantically validated programs.
        from tools.qualify_hia_selfhost_cli import inspect_executable
        for path in self.executables:
            self.assertFalse(inspect_executable(path.read_bytes())['dynamic_loader'])

    def test_direct_ELF_payload_pipeline_without_host_parser_and_real_program(self):
        from tools.qualify_hia_selfhost import compile_stage,invoke,hash_reference
        expected,_ = compile_stage(self.folder,'expected-sample',self.compiler,
            render_assembly(self.sample).encode())
        with (patch('json.loads',side_effect=AssertionError('host parser')),
              patch('json.dumps',side_effect=AssertionError('host encoder'))):
            output = self.run_cli(self.wire)
        self.assertEqual(output,expected.read_bytes())
        image = self.folder/'CLI-output.image.bin'; image.write_bytes(output)
        for i,data in enumerate((b'',b'no host compiler',bytes(range(256))*4)):
            receipt,value = invoke(self.folder,f'execute-{i}',image,data,capacity=1,workspace_size=1)
            self.assertEqual(receipt['core_u32'],hash_reference(data))
            self.assertEqual(value,bytes([hash_reference(data)&255]))

    def test_native_CLI_output_executes_in_fresh_HIA_observer_without_legacy_child(self):
        from tools.hia_selfhost_native_observer import invoke as native_invoke, frame as observer_frame
        from tools.qualify_hia_selfhost import hash_reference
        with (patch('json.loads',side_effect=AssertionError('foreign payload parser')),
              patch('json.dumps',side_effect=AssertionError('foreign payload encoder'))):
            code = self.run_cli(self.wire)
        image = self.folder/'CLI-to-native-observer.image.bin'
        image.write_bytes(code)
        for index,source in enumerate((b'',b'HIA JSON to execution',bytes(range(256))*4)):
            with patch('tools.qualify_hia_selfhost.invoke',side_effect=AssertionError('legacy child fallback')):
                receipt,output=native_invoke(self.folder,'CLI-native-observer-'+str(index),
                    self.observer,image,source,capacity=1,workspace_size=1,workspace_fill=90)
            self.assertEqual(receipt['core_u32'],hash_reference(source))
            self.assertEqual(output,bytes([hash_reference(source)&255]))
            self.assertTrue(receipt['source_unchanged'])
            self.assertTrue(receipt['fresh_native_exec'])
            self.assertFalse(receipt['successor_process_reuse'])
        trace=self.folder/'native-observer-composition.strace'
        source=b'actual standalone native execution'
        process=subprocess.run(['/usr/bin/strace','-qq','-o',str(trace),str(self.observer)],
            input=observer_frame(code,source,1,1,90),capture_output=True,timeout=15,
            cwd=self.folder,env={'PATH':'/nonexistent','HOME':'/nonexistent','LANG':'C'})
        self.assertEqual((process.returncode,process.stderr),(0,b''))
        self.assertEqual(process.stdout[:8],b'HIAOBR02')
        self.assertEqual(struct.unpack_from('<Q',process.stdout,8)[0],hash_reference(source))
        # bytesum.hiaasm deliberately stores the checksum into BOTH output
        # and workspace. Verify both actual stores, not an assumed untouched
        # workspace fill byte.
        self.assertEqual(process.stdout[24:],source+bytes([hash_reference(source)&255])*2)
        calls=re.findall(r'^([a-z0-9_]+)\(',trace.read_text(),re.MULTILINE)
        self.assertEqual(set(calls),{'execve','prctl','prlimit64','mmap','mprotect',
                                    'clock_gettime','read','write','exit'})
        self.assertEqual(calls.count('execve'),1)
        self.assertEqual(calls.count('mprotect'),1)
        self.assertIn('PROT_READ|PROT_EXEC',trace.read_text())

    def test_whole_original_and_modified_compilers_have_separate_fixed_points(self):
        from tools.qualify_hia_selfhost import compile_stage
        for index,wire in enumerate(self.wires):
            output = self.run_cli(wire)
            expected,_ = compile_stage(self.folder,f'expected-compiler-{index}',self.compiler,
                (self.original,self.modified)[index])
            self.assertEqual(output,expected.read_bytes())
            if index == 0: self.assertEqual(output,self.compiler.read_bytes())
            else: self.assertNotEqual(output,self.compiler.read_bytes())
            previous = self.folder/f'JSON-chain-{index}-G0.bin'; previous.write_bytes(output)
            images = [output]
            for generation in (1,2):
                following,_ = compile_stage(self.folder,f'JSON-chain-{index}-G{generation}',previous,
                    (self.original,self.modified)[index])
                images.append(following.read_bytes())
                previous = following
            self.assertEqual(images[1],images[2])
            if index == 0: self.assertEqual(images[0],images[1])
            else: self.assertNotEqual(images[2],self.compiler.read_bytes())

    def test_syscall_trace_has_no_runtime_interpreter_loader_or_filesystem_access(self):
        trace = self.folder/'native-json-cli.strace'
        result = subprocess.run(['strace','-qq','-o',str(trace),str(self.executables[0])],
            input=self.wire,capture_output=True,timeout=15,cwd=self.folder)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stderr,b'')
        calls = re.findall(r'^([a-z0-9_]+)\(',trace.read_text(),re.MULTILINE)
        self.assertEqual(calls.count('execve'),1)
        self.assertEqual(calls.count('mmap'),1)
        self.assertTrue({'read','write','exit'} <= set(calls))
        self.assertEqual(set(calls),{'execve','mmap','read','write','exit'})

    def test_JSON_to_standalone_compiler_original_and_modified_native_exec_chains(self):
        from tools.qualify_hia_selfhost import compile_stage
        from tools.qualify_hia_selfhost_cli import inspect_executable
        stable = []
        self.exec_chain_observations = []
        for index,(wire,source) in enumerate(zip(self.exec_wires,self.exec_sources)):
            expected,_=compile_stage(self.folder,f'exec-reference-{index}',self.compiler,source)
            with (patch('json.loads',side_effect=AssertionError('foreign payload parser')),
                  patch('json.dumps',side_effect=AssertionError('foreign payload serializer')),
                  patch('tools.qualify_hia_selfhost.compile_stage',side_effect=AssertionError('foreign build driver'))):
                raw=self.run_cli(wire,profile=2)
            self.assertEqual(raw,expected.read_bytes())
            generations=[raw]
            for generation in (1,2):
                path=self.folder/f'JSON-native-exec-{index}-{generation}'
                path.write_bytes(generations[-1]);path.chmod(0o700)
                self.assertFalse(inspect_executable(path.read_bytes())['dynamic_loader'])
                command=[str(path)]
                trace=self.folder/f'JSON-native-exec-{index}-{generation}.strace'
                if generation==2:command=['/usr/bin/strace','-qq','-o',str(trace),*command]
                process=subprocess.run(command,input=source,capture_output=True,timeout=15,
                    cwd=self.folder,env={'PATH':'/nonexistent','HOME':'/nonexistent','LANG':'C'})
                stdout=self.folder/f'JSON-native-exec-{index}-{generation}.stdout.bin'
                stdout.write_bytes(process.stdout)
                self.exec_chain_observations.append({'compiler_index':index,'generation':generation,
                    'compiler_sha256':sha256(path.read_bytes()).hexdigest(),
                    'input_sha256':sha256(source).hexdigest(),'stdout_sha256':sha256(process.stdout).hexdigest(),
                    'stdout_path':str(stdout),'returncode':process.returncode,'stderr_hex':process.stderr.hex()})
                self.assertEqual((process.returncode,process.stderr),(0,b''))
                if generation==2:
                    calls=re.findall(r'^([a-z0-9_]+)\(',trace.read_text(),re.MULTILINE)
                    self.assertEqual(set(calls),{'execve','mmap','read','write','exit'})
                    self.assertEqual(calls.count('execve'),1)
                generations.append(process.stdout)
            self.assertEqual(generations[1],generations[2])
            if index==0:self.assertEqual(generations[0],generations[1])
            else:self.assertNotEqual(generations[0],generations[1])
            stable.append(generations[2])
        self.assertNotEqual(stable[0],stable[1])

    def test_exec_profile_runs_unrelated_VM_oracle_and_refuses_ABI_switches(self):
        from tools.qualify_hia_selfhost_cli import inspect_executable
        source=self.exec_reference['echo_source'].encode().replace(b'v8 selfhost\n',b'v8 selfhost_exec\n',1)
        value=assemble_program(source).as_dict()
        raw=self.run_cli(json.dumps(value).encode(),profile=2)
        self.assertFalse(inspect_executable(raw)['libc'])
        executable=self.folder/'JSON-native-echo';executable.write_bytes(raw);executable.chmod(0o700)
        for row in self.exec_reference['echo']:
            process=subprocess.run([str(executable)],input=bytes.fromhex(row['input_hex']),
                capture_output=True,timeout=15,env={'PATH':'/nonexistent','HOME':'/nonexistent'})
            self.assertEqual((process.returncode,process.stdout,process.stderr),
                             (0,bytes.fromhex(row['output_hex']),b''))
        trace=self.folder/'JSON-native-echo.strace'
        process=subprocess.run(['/usr/bin/strace','-qq','-o',str(trace),str(executable)],
            input=b'Z',capture_output=True,timeout=15)
        self.assertEqual((process.returncode,process.stdout,process.stderr),(0,b'Z',b''))
        calls=re.findall(r'^([a-z0-9_]+)\(',trace.read_text(),re.MULTILINE)
        self.assertEqual(set(calls),{'execve','mmap','read','write','exit'})
        self.assertEqual(calls.count('execve'),1)
        for profile in (0,1):self.run_cli(json.dumps(value).encode(),2,profile=profile)
        for candidate in (self.sample,{**value,'module':'selfhost_elf'},
                          {**value,'exports':[]},self.export_documents[0]):
            self.run_cli(json.dumps(candidate).encode(),2,profile=2)
        scalar=copy.deepcopy(self.export_documents[0]);scalar.pop('exports')
        scalar['module']='selfhost_exec'
        self.run_cli(json.dumps(scalar).encode(),2,profile=2)  # semantic byte-ABI refusal

    def test_semantic_refusals_wire_depth_limits_and_explicit_ELF_selection(self):
        bad = copy.deepcopy(self.sample)
        bad['functions'][0]['blocks'][0]['ops'][0]['args'] = ['undefined_value']
        for value in (bad,{**self.sample,'exports':[]},{**self.sample,'module':'selfhost_exec'},
                      {**self.sample,'module':'selfhost_elf'}):
            self.run_cli(json.dumps(value).encode(),2)
        for data in (b'',b'{"x":0,"\\u0078":1}',b'"\\ud800"',self.wire+b'null'):
            self.run_cli(data,2)
        self.run_cli(b'['*129+b'0'+b']'*129,3)
        self.run_cli(b'['+b'0,'*((1<<20)-1)+b'0]',3)
        padded = self.wire + b' ' * ((8<<20)-len(self.wire))
        self.assertEqual(self.run_cli(padded),self.run_cli(self.wire))
        self.run_cli(padded+b' ',3)
        self.run_cli(self.wire,2,profile=1)
        from tools.qualify_hia_selfhost import compile_stage,invoke,hash_reference
        elf_program = {**self.sample,'module':'selfhost_elf'}
        actual = self.run_cli(json.dumps(elf_program).encode(),profile=1)
        expected,_ = compile_stage(self.folder,'expected-elf',self.compiler,render_assembly(elf_program).encode())
        self.assertEqual(actual,expected.read_bytes())
        obj,library = self.folder/'result.o',self.folder/'result.so'
        obj.write_bytes(actual)
        subprocess.run(['cc','-shared','-Wl,-z,defs','-Wl,-z,noexecstack',str(obj),'-o',str(library)],
            check=True,capture_output=True)
        receipt,value = invoke(self.folder,'execute-elf',library,b'elf',image_format='linked-selfhost',
            capacity=1,workspace_size=1)
        self.assertEqual(receipt['core_u32'],hash_reference(b'elf'))
        self.assertEqual(value,bytes([hash_reference(b'elf')&255]))

    def test_actual_native_codegen_output_capacity_refuses_without_partial_stdout(self):
        from tools.qualify_hia_selfhost_cli import output_capacity_source
        value = assemble_program(output_capacity_source()).as_dict()
        self.run_cli(json.dumps(value,separators=(',',':')).encode(),3)

    def test_standalone_JSON_to_two_export_objects_to_real_typed_C_executable(self):
        from hepta.object_symbols import inspect_object_symbols
        objects=[];defined=set()
        # No host payload parser/renderer/verifier/code generator may produce
        # either object. The actual standalone ELF executes both HIA stages.
        with (patch('json.loads',side_effect=AssertionError('foreign payload parser')),
              patch('json.dumps',side_effect=AssertionError('foreign payload serializer')),
              patch('tools.qualify_hia_selfhost.compile_stage',side_effect=AssertionError('foreign compiler driver'))):
            raw_objects=[self.run_cli(wire,profile=1) for wire in self.export_wires]
        for index,(raw,value) in enumerate(zip(raw_objects,self.export_documents)):
            symbols=inspect_object_symbols(raw,'ELF64',62)
            self.assertEqual(symbols['defined'],frozenset(value['exports']))
            self.assertEqual(symbols['undefined'],frozenset({'calloc','free'}))
            self.assertTrue(defined.isdisjoint(symbols['defined']))
            self.assertNotIn('private_value',symbols['defined'])
            defined.update(symbols['defined'])
            path=self.folder/f'CLI-export-{index}.o';path.write_bytes(raw);objects.append(path)
        types='uint8_t,uint16_t,uint32_t,uint64_t,uintptr_t,int8_t,int16_t,int32_t,int64_t,intptr_t,bool,uint8_t,uint16_t,uint32_t,uint64_t,uintptr_t'
        arguments='UINT8_C(250),UINT16_C(65000),UINT32_C(4000000000),UINT64_MAX-9,17,-120,-32000,-INT32_C(2000000000),INT64_MIN+7,-9,true,3,4,5,6,7'
        declarations=[];checks=[]
        for prefix in ('cli_left_','cli_right_'):
            declarations.extend((f'extern uint64_t {prefix}mixed({types});',
                f'extern uint64_t {prefix}via_private(void);',f'extern uintptr_t {prefix}allocated_size(uintptr_t);',
                f'extern int8_t {prefix}identity_i8(int8_t);',f'extern bool {prefix}identity_bool(bool);'))
            for name,argv in (('mixed',arguments),('via_private',''),('allocated_size','37'),
                              ('identity_i8','-120'),('identity_bool','true')):
                expected=self.export_reference[prefix+name]
                literal=f'UINT64_C({expected})' if expected>=0 else str(expected)
                checks.append(f'  if ({prefix}{name}({argv}) != {literal}) return {len(checks)+1};')
        driver=self.folder/'CLI-two-object-caller.c'
        driver.write_text('#include <stdint.h>\n#include <stdbool.h>\n'+'\n'.join(declarations)
            +'\nint main(void) {\n'+'\n'.join(checks)+'\n  return 0;\n}\n')
        executable=self.folder/'CLI-two-object-caller'
        subprocess.run(['cc','-std=c11','-Werror','-Wl,-z,defs,-z,noexecstack',str(driver),
            *map(str,objects),'-o',str(executable)],check=True,capture_output=True)
        result=subprocess.run([str(executable)],capture_output=True,timeout=15)
        self.assertEqual((result.returncode,result.stdout,result.stderr),(0,b'',b''))

    def test_explicit_exports_cannot_switch_ABI_or_hide_invalid_private_semantics(self):
        self.run_cli(self.export_wires[0],2)  # nonempty metadata never chooses ELF
        value=copy.deepcopy(self.export_documents[0])
        bad=[]
        for exports in ([],[value['exports'][0]]*2,['missing_export'],['malloc']):
            bad.append({**value,'exports':exports})
        private=copy.deepcopy(value)
        next(f for f in private['functions'] if f['name']=='private_value')['blocks'][0]['term']['values']=['undefined']
        bad.append(private)
        for candidate in bad:self.run_cli(json.dumps(candidate).encode(),2,profile=1)

    def test_actual_descriptor_usage_and_memory_failures(self):
        from tools.qualify_hia_selfhost_cli import execute
        for index,(mode,arguments,status) in enumerate((('closed-stdin',(),4),
                ('full-stdout',(),4),('mmap-failure',(),4),('ordinary',('unexpected',),64))):
            receipt,output = execute(self.folder,f'CLI-failure-{index}',self.executables[0],self.wire,
                mode=mode,arguments=arguments)
            self.assertEqual(receipt['returncode'],status)
            self.assertTrue(receipt['cleanup']['complete'])
            self.assertEqual(output,b'')
            self.assertEqual(receipt['stderr_hex'],'')


if __name__ == '__main__': unittest.main()
