"""Final-ELF, induction, mutation, real tail and no-overread SIMD controls."""
from __future__ import annotations

from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
import ctypes
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_program import verify_program
from hepta.hia_safe_core_elf import _ELF, SafeCoreELFRejected
from hepta.hia_verified_simd import simd_kernel_program, emit_verified_simd
from hepta.hia_verified_simd_check import (
    VerifiedSIMDRejected, decode_simd, recognize_simd_core, validate_verified_simd_artifact,
)

AVAILABLE = platform.system() == 'Linux' and platform.machine().lower() in ('x86_64','amd64') and shutil.which('ld') and importlib.util.find_spec('z3')


@unittest.skipUnless(AVAILABLE, 'Linux x86-64, GNU ld and pinned z3 are required')
class VerifiedSIMDTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory(prefix='hia-verified-simd-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root=Path(cls.temporary.name)
        cls.cases={}
        for kind in ('sum_u8','all_zero_u8','copy_u8'):
            core=simd_kernel_program(kind); image=emit_verified_simd(core)
            obj=cls.root/(kind+'.o'); final=obj.with_suffix('.so'); obj.write_bytes(image.object_bytes)
            result=subprocess.run(['ld','-m','elf_x86_64','-shared','-z','defs','-z','noexecstack',
                '-z','relro','-z','now','--hash-style=both','--build-id=none',str(obj),'-lc','-o',str(final)],capture_output=True,text=True)
            if result.returncode: raise AssertionError(result.stderr)
            proof=validate_verified_simd_artifact(core,image.object_bytes,final.read_bytes())
            cls.cases[kind]=(core,image,final,proof)

    def check_mutated(self,kind,patches,*,counterexample=False):
        core,image,final,_=self.cases[kind]
        object_bytes,final_bytes=bytearray(image.object_bytes),bytearray(final.read_bytes())
        original=image.text_bytes
        for before,after in patches:
            self.assertEqual(len(before),len(after)); self.assertEqual(original.count(before),1)
            offset=original.index(before)
            for data,elfkind in ((object_bytes,1),(final_bytes,3)):
                at=_ELF(bytes(data),elfkind).section('.text')['offset']+offset
                data[at:at+len(before)]=after
        with self.assertRaises(VerifiedSIMDRejected) as caught:
            validate_verified_simd_artifact(core,bytes(object_bytes),bytes(final_bytes))
        if counterexample:
            self.assertIsNotNone(caught.exception.counterexample)
            self.assertFalse(caught.exception.validation['ok'])
        return caught.exception

    def test_three_complete_cores_bind_direct_final_images(self):
        for kind,(core,image,final,proof) in self.cases.items():
            with self.subTest(kind=kind):
                self.assertEqual(recognize_simd_core(core),(kind,'calculate'))
                self.assertEqual(proof['subject']['core_sha256'],core.sha256)
                self.assertEqual(proof['subject']['final_image_sha256'],sha256(final.read_bytes()).hexdigest())
                self.assertEqual(proof['image_binding']['entry_offset'],0)
                self.assertEqual(proof['image_binding']['function_shape'],'direct_entry')
                self.assertEqual([o['result'] for o in proof['obligations']],['sat']+['unsat']*9)
                self.assertTrue(proof['claims']['inductive_loop_model_checked'])
                self.assertFalse(proof['claims']['foreign_pointer_liveness_proved'])
                self.assertFalse(proof['claims']['whole_language_soundness_proved'])
                self.assertEqual(proof['model_counts']['loop_backedges'],2)

    def test_checker_does_not_reemit_the_producer(self):
        core,image,final,_=self.cases['sum_u8']
        with patch('hepta.hia_verified_simd.emit_verified_simd',side_effect=AssertionError('producer invoked')):
            self.assertTrue(validate_verified_simd_artifact(core,image.object_bytes,final.read_bytes())['ok'])

    def test_parallel_validations_use_independent_solver_contexts(self):
        cases=[(core,image.object_bytes,path.read_bytes()) for core,image,path,_ in self.cases.values()]
        with ThreadPoolExecutor(max_workers=3) as pool:
            results=list(pool.map(lambda args:validate_verified_simd_artifact(*args),cases))
        self.assertTrue(all(r['ok'] and r['complete'] for r in results))
        self.assertEqual({r['kind'] for r in results},{'sum_u8','all_zero_u8','copy_u8'})

    def test_native_all_tail_lengths_and_large_buffers(self):
        lengths=list(range(129))+[255,256,257,1023,1024,1025,4095,4096,4097,65536]
        functions={}
        for kind,(_,_,path,_) in self.cases.items():
            fn=ctypes.CDLL(str(path)).calculate; fn.restype=ctypes.c_uint64
            fn.argtypes=([ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64,ctypes.c_uint64]
                         if kind=='copy_u8' else [ctypes.c_void_p,ctypes.c_uint64,ctypes.c_uint64])
            functions[kind]=fn
        for n in lengths:
            for offset in (0,1,7,15):
                values=bytes((i*173+29)%256 for i in range(n))
                src=ctypes.create_string_buffer(b'X'*offset+values+b'Z'*16)
                dst=ctypes.create_string_buffer(b'Q'*(offset+n+16))
                source,destination=ctypes.addressof(src)+offset,ctypes.addressof(dst)+offset
                self.assertEqual(functions['sum_u8'](source,n+16,n),sum(values))
                self.assertEqual(functions['all_zero_u8'](source,n+16,n),int(not any(values)))
                self.assertEqual(functions['copy_u8'](destination,n+16,source,n+16,n),n)
                self.assertEqual(dst.raw[:offset+n+16],b'Q'*offset+values+b'Q'*16)
                zero=ctypes.create_string_buffer(n+1)
                self.assertEqual(functions['all_zero_u8'](zero,n,n),1)
                if n:
                    zero[n-1]=b'\x80'
                    self.assertEqual(functions['all_zero_u8'](zero,n,n),0)
        self.assertEqual(functions['sum_u8'](None,0,0),0)
        self.assertEqual(functions['all_zero_u8'](None,0,0),1)
        self.assertEqual(functions['copy_u8'](None,0,None,0,0),0)

    def test_sum_vector_arithmetic_mutation_is_refuted(self):
        error=self.check_mutated('sum_u8',[(bytes.fromhex('660fd4c1'),bytes.fromhex('660ffbc1'))],counterexample=True)
        self.assertEqual(error.counterexample['obligation'],'vector_sum_induction')

    def test_persistent_zero_register_is_part_of_induction(self):
        # The first chunk remains correct, but using its SAD result as the
        # zero operand in the next iteration corrupts bytes. Single-step-only
        # validation must not accidentally admit this paired mutation.
        self.check_mutated('sum_u8',[(bytes.fromhex('660ff6ca'),bytes.fromhex('660ff6d1')),
                                   (bytes.fromhex('660fd4c1'),bytes.fromhex('660fd4c2'))],counterexample=True)

    def test_horizontal_shift_mutation_is_refuted(self):
        self.check_mutated('sum_u8',[(bytes.fromhex('660f73d808'),bytes.fromhex('660f73d800'))],counterexample=True)

    def test_scalar_tail_subtraction_is_refuted(self):
        self.check_mutated('sum_u8',[(bytes.fromhex('4c01c84883c701'),bytes.fromhex('4c29c84883c701'))],counterexample=True)

    def test_zero_scan_xor_cancellation_is_refuted(self):
        self.check_mutated('all_zero_u8',[(bytes.fromhex('660febc1'),bytes.fromhex('660fefc1'))],counterexample=True)

    def test_copy_wrong_vector_register_is_refuted(self):
        self.check_mutated('copy_u8',[(bytes.fromhex('f30f7f0f'),bytes.fromhex('f30f7f07'))],counterexample=True)

    def test_copy_wrong_tail_register_is_refuted(self):
        self.check_mutated('copy_u8',[(bytes.fromhex('44888f00000000'),bytes.fromhex('40888700000000'))],counterexample=True)

    def test_stride_and_memory_width_controls_are_rejected(self):
        self.check_mutated('sum_u8',[(bytes.fromhex('4983ea10'),bytes.fromhex('4983ea0f'))])
        self.check_mutated('copy_u8',[(bytes.fromhex('4883c210'),bytes.fromhex('4883c211'))])
        self.check_mutated('sum_u8',[(bytes.fromhex('4c0fb68f00000000'),bytes.fromhex('4c0fb68f01000000'))])

    def test_second_vector_memory_access_is_rejected(self):
        self.check_mutated('sum_u8',[(bytes.fromhex('660ff6ca'),bytes.fromhex('f30f6f0a'))])

    def test_saved_register_clobber_is_rejected(self):
        self.check_mutated('sum_u8',[(bytes.fromhex('4c01c84883c701'),bytes.fromhex('4c01cb4883c701'))])

    def test_core_changed_recurrence_effect_or_preflight_is_rejected(self):
        for action in ('sum','stride','guard','store'):
            d=deepcopy(self.cases['sum_u8'][0].as_dict())
            b={x['id']:x for x in d['functions'][0]['blocks']}
            if action=='sum': b['body']['ops'][2]['op']='int.sub.wrap'
            elif action=='stride': b['body']['ops'][3]['attrs']['value']=2
            elif action=='guard': b['entry']['ops'][1]['op']='compare.lt'
            else: d['functions'][0]['effects'].append('write')
            checked=verify_program(d)
            with self.subTest(action=action),self.assertRaises(VerifiedSIMDRejected): emit_verified_simd(checked)

    def test_immutable_bytes_and_complete_decoder_are_required(self):
        core,image,final,_=self.cases['sum_u8']
        for data in (bytearray(image.object_bytes),memoryview(image.object_bytes)):
            with self.assertRaises(VerifiedSIMDRejected): validate_verified_simd_artifact(core,data,final.read_bytes())
        for text in (bytes.fromhex('f30f6f'),bytes.fromhex('660fefc0cc'),bytes.fromhex('e901000000c3'),bytes.fromhex('f3660f6f0f')):
            with self.assertRaises(VerifiedSIMDRejected): decode_simd(text)

    def test_final_only_mutation_cannot_reuse_object_identity(self):
        core,image,final,_=self.cases['sum_u8']; data=bytearray(final.read_bytes())
        at=_ELF(bytes(data),3).section('.text')['offset']; data[at]^=1
        with self.assertRaises(SafeCoreELFRejected): validate_verified_simd_artifact(core,image.object_bytes,bytes(data))

    def test_query_archive_contains_executed_obligations(self):
        core,image,final,_=self.cases['copy_u8']; path=self.root/'queries'
        r=validate_verified_simd_artifact(core,image.object_bytes,final.read_bytes(),query_directory=path)
        self.assertEqual(len(list(path.glob('*.smt2'))),len(r['obligations']))
        self.assertEqual(json.loads((path/'validation.json').read_text())['subject'],r['subject'])
        for i,row in enumerate(r['obligations'],1):
            q=(path/(str(i).zfill(2)+'-'+row['name']+'.smt2')).read_bytes()
            self.assertEqual(sha256(q).hexdigest(),row['query_sha256'])

    def test_invalid_native_ranges_abort_before_touching_memory(self):
        read_cases=[(0,1,1),(0,0,1),((1<<64)-1,2,2),(1,0,1)]
        for kind in ('sum_u8','all_zero_u8'):
            path=self.cases[kind][2]
            for pointer,extent,count in read_cases:
                code='import ctypes,resource;resource.setrlimit(resource.RLIMIT_CORE,(0,0));f=ctypes.CDLL('+repr(str(path))+').calculate;f.argtypes=[ctypes.c_void_p,ctypes.c_uint64,ctypes.c_uint64];f.restype=ctypes.c_uint64;f('+','.join(map(str,(pointer,extent,count)))+')'
                r=subprocess.run([sys.executable,'-c',code],capture_output=True,timeout=10)
                self.assertEqual(r.returncode,-signal.SIGABRT,(kind,pointer,r.stderr))
        path=self.cases['copy_u8'][2]
        for args in ((0,1,0,1,1),(1,1,2,1,2),((1<<64)-1,2,1,2,2),(1,2,(1<<64)-1,2,2),(1,8,2,8,8)):
            code='import ctypes,resource;resource.setrlimit(resource.RLIMIT_CORE,(0,0));f=ctypes.CDLL('+repr(str(path))+').calculate;f.argtypes=[ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64,ctypes.c_uint64];f.restype=ctypes.c_uint64;f('+','.join(map(str,args))+')'
            r=subprocess.run([sys.executable,'-c',code],capture_output=True,timeout=10)
            self.assertEqual(r.returncode,-signal.SIGABRT,(args,r.stderr))

    @unittest.skipUnless(shutil.which('cc'),'C compiler required for isolated real guard-page test')
    def test_real_guard_pages_cover_every_vector_tail(self):
        source=self.root/'guard_pages.c'; binary=source.with_suffix('')
        source.write_text(r'''
#define _GNU_SOURCE
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
typedef uint64_t (*reduce_t)(const uint8_t*,uint64_t,uint64_t);
typedef uint64_t (*copy_t)(uint8_t*,uint64_t,const uint8_t*,uint64_t,uint64_t);
int main(int argc,char**argv){
  if(argc!=4)return 1;
  long page=sysconf(_SC_PAGESIZE);if(page!=4096)return 2;
  void*a=dlopen(argv[1],RTLD_NOW),*b=dlopen(argv[2],RTLD_NOW),*c=dlopen(argv[3],RTLD_NOW);
  if(!a||!b||!c)return 3;
  reduce_t sum=(reduce_t)dlsym(a,"calculate"),zero=(reduce_t)dlsym(b,"calculate");
  copy_t copy=(copy_t)dlsym(c,"calculate");if(!sum||!zero||!copy)return 4;
  uint8_t*s=mmap(0,page*3,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
  uint8_t*d=mmap(0,page*3,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
  if(s==MAP_FAILED||d==MAP_FAILED)return 5;
  if(mprotect(s+page,page,PROT_READ|PROT_WRITE)||mprotect(d+page,page,PROT_READ|PROT_WRITE))return 6;
  for(unsigned n=1;n<=4096;n++){
    uint8_t*sp=s+2*page-n,*dp=d+2*page-n;uint64_t expected=0;
    for(unsigned i=0;i<n;i++){sp[i]=(uint8_t)(i*37+11);dp[i]=0;expected+=sp[i];}
    if(sum(sp,n,n)!=expected||zero(sp,n,n)!=0||copy(dp,n,sp,n,n)!=n)return 7;
    for(unsigned i=0;i<n;i++)if(dp[i]!=sp[i])return 8;
    for(unsigned i=0;i<n;i++)sp[i]=0;
    if(zero(sp,n,n)!=1)return 9;
  }
  puts("4096 exact-end ranges passed");return 0;
}
''')
        r=subprocess.run(['cc','-O2','-Wall','-Wextra',str(source),'-ldl','-o',str(binary)],capture_output=True,text=True,timeout=30)
        self.assertEqual(r.returncode,0,r.stderr)
        r=subprocess.run([str(binary)]+[str(self.cases[k][2]) for k in ('sum_u8','all_zero_u8','copy_u8')],capture_output=True,text=True,timeout=30)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(r.stdout.strip(),'4096 exact-end ranges passed')


if __name__=='__main__': unittest.main()
