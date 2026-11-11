"""Actual shared ELF, Core VM, protocol, kernel limit and ownership controls."""
from pathlib import Path
import errno
import json
import os
import platform
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import hia_selfhost_linked_observer as linked
from tools.hia_selfhost_native_observer import execute, frame, invoke as native_invoke


class LinkedObserverSourceTests(unittest.TestCase):
    def test_generated_sources_and_independent_fixed_bridge_bytes(self):
        from hepta.hia_agent_assembly import render_assembly
        from tools.generate_hia_artifact_publication import document
        from tools import generate_hia_linked_observer as generator
        for name, source in (('policy', generator.policy_source()), ('packer', generator.packer_source())):
            self.assertEqual(getattr(linked, name.upper()).read_text(),
                             render_assembly(document(source, 'linked_observer_'+name)))
        self.assertEqual(generator.assembled_bridge(), (generator.BRIDGE, generator.BRIDGE_HOLES))

    def test_independent_VM_all_continuations_and_all_packer_bytes(self):
        reference = linked.independent_reference()
        self.assertTrue(reference['before_B0'])
        self.assertEqual([x['action'] for x in reference['policy_observations']], list(range(1,9))+[0])
        self.assertTrue(all(r['every_output_byte_compared'] for r in reference['packer_observations']))

    def test_policy_failure_feedback_and_admission_remain_HIA_decisions(self):
        from hepta.hia_agent_assembly import assemble_program
        checked = assemble_program(linked.POLICY.read_bytes())
        good = frame(b'ELF', b'x', 0, 0, 0)
        cases = [(0, 2, (), b'', 64), (99, 1, (), good, 70)]
        for phase in (1,2,4,5,6,7,8):
            cases.append((phase, 1, ((16,(1<<64)-5),), good, 1 if phase in (4,8) else 4))
        cases += [(3,1,((16,0),),good,1), (2,1,((16,0),(24,7),(32,7)),good,4)]
        for malformed in (b'', good[:-1], good+b'x', b'BADMAGIC'+good[8:]):
            cases.append((1,1,(),malformed,2))
        for phase,argc,feedback,source,exitcode in cases:
            state=bytearray(512);struct.pack_into('<2Q',state,0,phase,argc)
            for at,value in feedback:struct.pack_into('<Q',state,at,value)
            returned,output,_,_=linked._vm(checked,source,bytes(512),bytes(state))
            self.assertEqual((returned,struct.unpack_from('<Q',output)[0]),([0],exitcode))


@unittest.skipUnless(platform.system()=='Linux' and platform.machine().lower() in ('x86_64','amd64')
                     and shutil.which('ld') and shutil.which('as'), 'Linux x86-64 GNU ld/as required')
class LinkedObserverNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.qualify_hia_selfhost import build_seed, compile_stage, SOURCE
        cls.temp=tempfile.TemporaryDirectory(prefix='hia-linked-observer-')
        cls.root=Path(cls.temp.name)
        cls.reference=linked.independent_reference()
        seed,_=build_seed(cls.root)
        cls.compiler,_=compile_stage(cls.root,'B1',seed,SOURCE.read_bytes(),image_format='seed-shared')
        cls.observer,cls.receipt=linked.build(cls.root,cls.compiler,cls.reference)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def library(self,name,body=None,assembly=None,symbol='f0'):
        source=self.root/(name+'.S');obj=self.root/(name+'.o');image=self.root/(name+'.so')
        if assembly is None:
            assembly='.text\n.global '+symbol+'\n.type '+symbol+',@function\n'+symbol+':\n.byte '+','.join(str(x) for x in body)+'\n'
        source.write_text(assembly+'\n.section .note.GNU-stack,"",@progbits\n')
        subprocess.run(['as','--64',str(source),'-o',str(obj)],check=True,capture_output=True)
        subprocess.run(['ld','-shared','-o',str(image),str(obj)],check=True,capture_output=True)
        self.assertEqual(image.read_bytes()[:4],b'\x7fELF')
        return image

    def call(self,name,image,source=b'',capacity=32,workspace_size=128,workspace_fill=90,**options):
        return native_invoke(self.root,name,self.observer,image,source,
            capacity=capacity,workspace_size=workspace_size,workspace_fill=workspace_fill,
            image_format='linked-selfhost',**options)

    def test_actual_HIA_emission_every_byte_and_foreign_dynamic_dependencies(self):
        from tools.generate_hia_linked_observer import reference_image
        policy=(self.root/'linked-observer-policy.image.bin').read_bytes()
        self.assertEqual(self.observer.read_bytes(),reference_image(policy))
        self.assertTrue(self.receipt['actual_policy_vm_packing']['every_output_byte_compared'])
        self.assertTrue(self.receipt['independent_reference_before_B0'])
        inspected=subprocess.run(['readelf','-d','-l',str(self.observer)],check=True,capture_output=True,text=True).stdout
        for name in ('libdl.so.2','libc.so.6','ld-linux-x86-64.so.2','GNU_RELRO'):
            self.assertIn(name,inspected)

    def test_full_foreign_u64_return_and_buffer_matrix_match_independent_loader(self):
        from tools.qualify_hia_selfhost import invoke
        image=self.library('full-u64',bytes.fromhex('48 b8 2a 00 00 00 ef be ad de c3'))
        for index,(source,capacity,fill) in enumerate((s,c,f) for s in (b'',b'A\0\xff'*137)
                for c in (0,1,257) for f in (0,90,255)):
            name='matrix-'+str(index)
            new,out=self.call(name,image,source,capacity,1032,fill)
            old,raw=invoke(self.root,name+'-old',image,source,image_format='linked-selfhost',
                           capacity=capacity,workspace_size=1032,workspace_fill=fill)
            self.assertEqual(out,raw)
            for key in ('status','result_u64','abi_status','core_u32','source_unchanged','output_unchanged',
                        'workspace_header','source_sha256','output_sha256','limits','return_encoding'):
                self.assertEqual(new[key],old[key],(name,key))
            self.assertEqual(new['format'],'linked-selfhost')
            self.assertTrue(new['fresh_native_exec'])
            self.assertFalse(new['successor_process_reuse'])

    def test_real_GNU_ld_calloc_free_relocations_are_resolved_and_executed(self):
        image=self.library('real-calloc',assembly='''
.text
.global f0
.type f0,@function
f0:
 push %rbp
 push %rbx
 push %r12
 mov %rdx,%r12
 mov $1,%edi
 mov $64,%esi
 call calloc@PLT
 test %rax,%rax
 je failed
 mov %rax,%rbx
 mov %rax,%rsi
 mov %r12,%rdi
 mov $8,%ecx
 rep movsq
 mov %rbx,%rdi
 call free@PLT
 mov $42,%eax
 jmp done
failed:
 mov $99,%eax
done:
 pop %r12
 pop %rbx
 pop %rbp
 ret
''')
        result,output=self.call('actual-calloc',image,capacity=64,workspace_size=0)
        self.assertEqual((result['status'],result['core_u32'],output),('returned',42,bytes(64)))
        from tools.qualify_hia_selfhost import invoke
        old,raw=invoke(self.root,'actual-calloc-old',image,b'',image_format='linked-selfhost',capacity=64,workspace_size=0)
        self.assertEqual((old['core_u32'],raw),(42,output))

    def test_actual_payload_and_executable_seals_and_image_close_after_dlsym(self):
        image=self.library('seals',assembly='''
.data
before: .quad 0
.section .init_array,"aw"
.quad init
.text
count:
 push %rbx
 mov $3,%ebx
 xor %r8d,%r8d
1:
 mov %ebx,%edi
 mov $1034,%esi
 xor %edx,%edx
 mov $72,%eax
 syscall
 cmp $15,%eax
 jne 2f
 inc %r8d
2:
 inc %ebx
 cmp $32,%ebx
 jne 1b
 mov %r8,%rax
 pop %rbx
 ret
init:
 sub $8,%rsp
 call count
 mov %rax,before(%rip)
 add $8,%rsp
 ret
.global f0
.type f0,@function
f0:
 sub $8,%rsp
 call count
 add $8,%rsp
 mov before(%rip),%rdx
 shl $32,%rdx
 or %rdx,%rax
 ret
''')
        result,_=self.call('seals-observed',image,capacity=0,workspace_size=0)
        self.assertEqual(result['result_u64'],(2<<32)|1)

    def test_source_mutation_custom_preimages_and_real_traps_equal_original(self):
        from tools.qualify_hia_selfhost import invoke
        mutated=self.library('source-mutation',bytes.fromhex('c6 07 61 31 c0 c3'))
        result,_=self.call('source-mutation-run',mutated,b'XYZ')
        self.assertFalse(result['source_unchanged'])
        self.assertEqual((self.root/'source-mutation-run.modified-source.bin').read_bytes(),b'aYZ')
        for index,code in enumerate(('31 c0 c3','c6 02 63 31 c0 c3','c6 02 63 0f 0b')):
            image=self.library('trap-'+str(index),bytes.fromhex(code))
            for initial in (b'Z',b'\0Z\xff',b'\xff'*31):
                name='capture-'+str(index)+'-'+str(len(initial))
                new,out=self.call(name,image,b'input',capacity=len(initial),workspace_size=128,
                                  workspace_fill=255,output_initial=initial,observe_trap_writes=True)
                old,raw=invoke(self.root,name+'-old',image,b'input',image_format='linked-selfhost',
                    capacity=len(initial),workspace_size=128,workspace_fill=255,
                    output_initial=initial,observe_trap_writes=True)
                self.assertEqual((new['status'],out),(old['status'],raw))
                for key in ('available','initial_sha256','observed_sha256','observed_bytes','unchanged'):
                    self.assertEqual(new['shared_output_observation'][key],old['shared_output_observation'][key])
                if index==2:self.assertEqual((new['returncode'],old['returncode']),(-4,-4))

    def test_missing_symbol_bad_ELF_and_loader_relocation_failure_are_real_refusals(self):
        missing=self.library('missing-entry',b'\xc3',symbol='different')
        unresolved=self.library('missing-import',assembly='.text\n.global f0\nf0:\n jmp nonexistent_hia_import@PLT\n')
        invalid=self.root/'invalid.so';invalid.write_bytes(b'not ELF')
        for index,image in enumerate((missing,unresolved,invalid)):
            result,out=self.call('loader-failure-'+str(index),image)
            self.assertEqual((result['status'],result['returncode'],out),('child_failed',1,b''))

    def test_actual_kernel_limits_nondumpable_and_unexpected_stdout(self):
        # prlimit64(CPU) into workspace, followed by PR_GET_DUMPABLE.
        code=bytes.fromhex('41 54 49 89 d4 4d 89 c2 31 ff 31 f6 31 d2 b8 2e 01 00 00 0f 05'
          ' 49 8b 02 49 89 04 24 49 8b 42 08 49 89 44 24 08 bf 03 00 00 00 b8 9d 00 00 00 0f 05 41 5c c3')
        limits=self.library('kernel-limits',code)
        result,out=self.call('kernel-limits-run',limits,capacity=16,workspace_size=16)
        self.assertEqual((result['core_u32'],struct.unpack('<2Q',out)),(0,(10,10)))
        image=self.library('stdout-injection',bytes.fromhex('48 89 f2 48 89 fe bf 01 00 00 00 b8 01 00 00 00 0f 05 b8 2a 00 00 00 c3'))
        result,out=self.call('stdout-injection-run',image,b'injected-prefix')
        self.assertEqual((result['status'],out),('protocol_failed',b''))
        self.assertTrue((self.root/'stdout-injection-run.failure-stdout.raw').read_bytes().startswith(b'injected-prefixHIAOBR02'))

    def test_timeout_kills_and_reaps_actual_child_and_closes_parent_descriptor(self):
        image=self.library('blocks',assembly='''
.text
.global f0
f0:
 sub $8,%rsp
 mov $39,%eax
 syscall
 mov %rax,(%rsp)
 mov $1,%edi
 mov %rsp,%rsi
 mov $8,%edx
 mov $1,%eax
 syscall
1:
 mov $34,%eax
 syscall
 jmp 1b
''')
        before=len(list(Path('/proc/self/fd').iterdir()))
        with self.assertRaises(subprocess.TimeoutExpired) as raised:
            execute(self.observer.read_bytes(),frame(image.read_bytes(),b'',0,0,0),cwd=self.root,timeout=.1)
        pid=int.from_bytes(raised.exception.stdout,'little')
        self.assertGreater(pid,1)
        with self.assertRaises(ProcessLookupError):os.kill(pid,0)
        self.assertEqual(before,len(list(Path('/proc/self/fd').iterdir())))

    def test_bad_frame_bounds_and_argv_are_rejected_by_native_policy(self):
        image=self.library('inert',b'\xc3')
        good=frame(image.read_bytes(),b'',0,0,0)
        bad=[b'',good[:47],b'badMAGIC'+good[8:],good+b'\0',good[:-1]]
        for index in range(5):
            altered=bytearray(good);struct.pack_into('<Q',altered,8+index*8,(1<<64)-1);bad.append(bytes(altered))
        for value in (0,1,2,2147483648,(1<<64)-2):
            altered=bytearray(good);struct.pack_into('<Q',altered,48,value);bad.append(bytes(altered))
        for request in bad:
            observed=execute(self.observer.read_bytes(),request,cwd=self.root)
            self.assertEqual((observed.returncode,observed.stdout,observed.stderr),(2,b'',b''))
        observed=execute(self.observer.read_bytes(),good,cwd=self.root,arguments=('extra',))
        self.assertEqual((observed.returncode,observed.stdout),(64,b''))

    def test_selected_linked_has_no_fallback_and_seed_stays_independent(self):
        import tools.qualify_hia_selfhost as q
        image=self.library('selected',bytes.fromhex('b8 2a 00 00 00 c3'))
        with patch.object(q,'NATIVE_LINKED_OBSERVER',self.observer):
            new,_=q.invoke(self.root,'selected-run',image,b'',image_format='linked-selfhost',capacity=0,workspace_size=0)
            seed,_=q.invoke(self.root,'seed-retained',image,b'',image_format='seed-shared',capacity=0,workspace_size=0)
        self.assertEqual(new['transport'],'HIA-policy-dynamic-ELF-linked-observer-v1')
        self.assertNotIn('transport',seed)
        self.assertEqual(seed['return_encoding'],'packed-ABI-status-and-u32')
        with patch.object(q,'NATIVE_LINKED_OBSERVER',self.root/'missing-observer'):
            with self.assertRaises(FileNotFoundError):
                q.invoke(self.root,'no-fallback',image,b'',image_format='linked-selfhost',capacity=0,workspace_size=0)

    def test_prelaunch_failure_closes_shared_fd_and_source_bound_build_refuses_drift(self):
        image=self.library('storage-inert',b'\xc3')
        before=len(list(Path('/proc/self/fd').iterdir()))
        with patch.object(Path,'write_text',side_effect=OSError(errno.ENOSPC,'retained control')):
            with self.assertRaises(OSError):
                self.call('storage-failure',image,capacity=1,workspace_size=0,output_initial=b'Z')
        self.assertEqual(before,len(list(Path('/proc/self/fd').iterdir())))
        altered={**self.reference,'source_sha256':{}}
        with self.assertRaisesRegex(ValueError,'source identity differs'):
            linked.build(self.root,self.compiler,altered)


if __name__=='__main__':
    unittest.main()
