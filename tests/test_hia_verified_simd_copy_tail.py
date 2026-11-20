"""Native endpoint-copy effects only after final proof and fresh CPU admission."""
from __future__ import annotations

import ctypes
from hashlib import sha256
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest

from hepta.hia_machine_x64 import Code
from hepta.hia_verified_cpu import VerifiedCPURejected, probe_host_isa
from hepta.hia_verified_kernel import build_verified_kernel
from hepta.hia_verified_kernel_load import load_verified_simd_kernel
from hepta.hia_verified_simd import emit_verified_simd, simd_kernel_program
from hepta.hia_verified_simd_check import VerifiedSIMDRejected
from hepta.hia_verified_simd_wide import _copy_word, _memory
from tests.test_hia_verified_simd import AVAILABLE


HISTORICAL_COPY = {
    'avx2': ('04514f6bea6d407b5c69436f7d914ef313f2fca13fb63b4d606fdce6c02e20f4',
             '43b5477c865f22ecd0673b5ab3874ef5a95928bc61ccecd2900ab1c98840934c'),
    'avx512': ('67803976bf2c7ea29de6589d59119ca3eafa134c6af923a2a8e859e264955d20',
               '2298cfba5e3dba6fbba3a51e614efcf255451815013b02afe242e7d339de2d6c'),
}


@unittest.skipUnless(AVAILABLE, 'Linux x86-64, GNU ld and pinned Z3 are required')
class VerifiedCopyEndpointNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='hia-copy-endpoint-native-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.core = simd_kernel_program('copy_u8')
        cls.cases, cls.refusals = {}, {}
        features = set(probe_host_isa()['common_features'])
        for isa, needed in (('avx2', {'avx'}), ('avx512', {'avx', 'avx512f'})):
            image = emit_verified_simd(cls.core, isa=isa, copy_tail='endpoints')
            path = cls.root / ('endpoint-' + isa + '.so')
            if not needed <= features:
                try:
                    build_verified_kernel(cls.core, path, strategy='simd', simd_isa=isa,
                                          simd_copy_tail='endpoints')
                except VerifiedCPURejected as exc:
                    if path.exists() or 'does not enable' not in str(exc):
                        raise AssertionError('unsupported endpoint ISA was not refused before publication') from exc
                    cls.refusals[isa] = str(exc)
                else:
                    raise AssertionError('unsupported endpoint image was published')
                continue
            build = build_verified_kernel(cls.core, path, strategy='simd', simd_isa=isa,
                                          simd_copy_tail='endpoints')
            loaded = load_verified_simd_kernel(cls.core, image.object_bytes, path.read_bytes())
            cls.cases[isa] = (image, path, build, loaded)
        print('Endpoint native coverage: ' + str(len(cls.cases)) + ' proved/admitted images; ' +
              str(len(cls.refusals)) + ' unsupported images refused')

    def test_explicit_endpoint_copy_is_proved_and_bound_before_native_execution(self):
        self.assertEqual(set(self.cases) | set(self.refusals), {'avx2', 'avx512'})
        for isa, (image, path, build, loaded) in self.cases.items():
            with self.subTest(isa=isa):
                self.assertEqual(image.copy_tail, 'endpoints')
                self.assertTrue(build['validation']['ok'] and build['validation']['complete'])
                self.assertEqual(build['validation']['subject']['object_sha256'], sha256(image.object_bytes).hexdigest())
                self.assertEqual(build['validation']['subject']['final_image_sha256'], sha256(path.read_bytes()).hexdigest())
                self.assertTrue(loaded.mapping_admission['sealed_image_and_loaded_symbol_bound'])
                self.assertEqual(build['runtime_solver_calls'], 0)
                self.assertEqual(loaded.function(None, 0, None, 0, 0), 0)

    def test_all_short_suffixes_and_asymmetric_alignments_preserve_exact_effects(self):
        lengths = list(range(514)) + [1023, 1024, 1025, 4095, 4096, 4097, 65535, 65536]
        offsets = ((0, 0), (1, 7), (7, 1), (15, 31), (31, 15), (32, 63), (63, 32))
        for isa, (_, _, _, loaded) in self.cases.items():
            for n in lengths:
                values = bytes((i * 173 + 29) & 255 for i in range(n))
                for source_offset, destination_offset in offsets:
                    source_bytes = b'S' * source_offset + values + b'Z' * 65
                    destination_bytes = b'D' * destination_offset + b'Q' * n + b'Z' * 65
                    source = ctypes.create_string_buffer(source_bytes)
                    destination = ctypes.create_string_buffer(destination_bytes)
                    actual = loaded.function(ctypes.addressof(destination) + destination_offset, n + 65,
                                             ctypes.addressof(source) + source_offset, n + 65, n)
                    self.assertEqual(actual, n, (isa, n, source_offset, destination_offset))
                    self.assertEqual(source.raw[:len(source_bytes)], source_bytes)
                    self.assertEqual(destination.raw[:len(destination_bytes)],
                                     b'D' * destination_offset + values + b'Z' * 65,
                                     (isa, n, source_offset, destination_offset))

    def test_adjacent_nonoverlapping_ranges_work_in_both_address_orders(self):
        for isa, (_, _, _, loaded) in self.cases.items():
            for n in range(1, 258):
                values = bytes((i * 91 + 17) & 255 for i in range(n))
                for reverse in (False, True):
                    before = b'L' * 7 + (b'Q' * n + values if reverse else values + b'Q' * n) + b'R' * 9
                    memory = ctypes.create_string_buffer(before)
                    start = ctypes.addressof(memory) + 7
                    source, destination = (start + n, start) if reverse else (start, start + n)
                    self.assertEqual(loaded.function(destination, n, source, n, n), n, (isa, n, reverse))
                    self.assertEqual(memory.raw[:len(before)], b'L' * 7 + values + values + b'R' * 9)

    @unittest.skipUnless(shutil.which('cc'), 'C compiler required for exact start/end guard pages')
    def test_guard_pages_cover_both_ends_of_every_short_and_vector_range(self):
        source = self.root / 'endpoint-guard-pages.c'
        executable = source.with_suffix('')
        source.write_text(r'''
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>
typedef uint64_t (*copy_t)(uint8_t*,uint64_t,const uint8_t*,uint64_t,uint64_t);
int main(int argc,char**argv){
  struct rlimit limit={0,0};setrlimit(RLIMIT_CORE,&limit);
  if(argc!=2)return 1;
  size_t page=(size_t)sysconf(_SC_PAGESIZE);if(page!=4096)return 2;
  void* library=dlopen(argv[1],RTLD_NOW);if(!library)return 3;
  copy_t copy=(copy_t)dlsym(library,"calculate");if(!copy)return 4;
  uint8_t*s=mmap(0,page*3,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
  uint8_t*d=mmap(0,page*3,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
  if(s==MAP_FAILED||d==MAP_FAILED)return 5;
  if(mprotect(s+page,page,PROT_READ|PROT_WRITE)||mprotect(d+page,page,PROT_READ|PROT_WRITE))return 6;
  for(size_t n=1;n<=page;n++)for(unsigned source_end=0;source_end<2;source_end++)for(unsigned destination_end=0;destination_end<2;destination_end++){
    memset(s+page,0x6b,page);memset(d+page,0xa5,page);
    size_t so=source_end?page-n:0,doff=destination_end?page-n:0;
    uint8_t*sp=s+page+so,*dp=d+page+doff;
    for(size_t i=0;i<n;i++)sp[i]=(uint8_t)(i*37+11);
    if(copy(dp,n,sp,n,n)!=n||memcmp(dp,sp,n))return 7;
    for(size_t i=0;i<page;i++){
      if((i<doff||i>=doff+n)&&d[page+i]!=0xa5)return 8;
      uint8_t expected=(i<so||i>=so+n)?0x6b:(uint8_t)((i-so)*37+11);
      if(s[page+i]!=expected)return 9;
    }
  }
  puts("4096 lengths x 4 endpoint placements passed");return 0;
}
''')
        built = subprocess.run(['cc', '-O2', '-Wall', '-Wextra', str(source), '-ldl', '-o', str(executable)],
                               capture_output=True, text=True, timeout=30)
        self.assertEqual(built.returncode, 0, built.stderr)
        for isa, (_, path, _, _) in self.cases.items():
            result = subprocess.run([str(executable), str(path)], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, (isa, result.stdout, result.stderr))
            self.assertEqual(result.stdout.strip(), '4096 lengths x 4 endpoint placements passed')

    def test_invalid_ranges_abort_before_any_endpoint_memory_access(self):
        invalid = ((0, 1, 0, 1, 1), (1, 1, 2, 1, 2), ((1 << 64) - 1, 2, 1, 2, 2),
                   (1, 2, (1 << 64) - 1, 2, 2), (1, 8, 2, 8, 8), (2, 8, 1, 8, 8), (1, 8, 1, 8, 8))
        for isa, (_, path, _, _) in self.cases.items():
            for args in invalid:
                source = ('import ctypes,resource;resource.setrlimit(resource.RLIMIT_CORE,(0,0));'
                          'library=ctypes.CDLL(' + repr(str(path)) + ');f=library["calculate"];'
                          'f.restype=ctypes.c_uint64;'
                          'f.argtypes=[ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64,ctypes.c_uint64];'
                          'f(' + ','.join(map(str, args)) + ')')
                result = subprocess.run([sys.executable, '-B', '-c', source], capture_output=True, timeout=10)
                self.assertEqual(result.returncode, -signal.SIGABRT, (isa, args, result.stderr))

    def test_explicit_byte_tail_retains_exact_historical_objects(self):
        for isa, (text_hash, object_hash) in HISTORICAL_COPY.items():
            image = emit_verified_simd(self.core, isa=isa, copy_tail='byte')
            self.assertEqual(image.copy_tail, 'byte')
            self.assertEqual(sha256(image.text_bytes).hexdigest(), text_hash)
            self.assertEqual(sha256(image.object_bytes).hexdigest(), object_hash)
            self.assertNotEqual(image.text_bytes, emit_verified_simd(self.core, isa=isa, copy_tail='endpoints').text_bytes)

    def test_tail_selection_rejects_unreviewed_values_and_nonwide_targets(self):
        for value in (True, False, 0, 1, '', 'scalar', 'head', [], {}):
            with self.subTest(value=value), self.assertRaises(VerifiedSIMDRejected):
                emit_verified_simd(self.core, isa='avx2', copy_tail=value)
        with self.assertRaises(VerifiedSIMDRejected):
            emit_verified_simd(self.core, isa='sse2', copy_tail='endpoints')
        for kind in ('sum_u8', 'all_zero_u8'):
            with self.assertRaises(VerifiedSIMDRejected):
                emit_verified_simd(simd_kernel_program(kind), isa='avx512', copy_tail='endpoints')

    @unittest.skipUnless(shutil.which('as') and shutil.which('objcopy'), 'GNU as/objcopy required for encoder cross-check')
    def test_endpoint_instruction_bytes_match_the_independent_system_assembler(self):
        lines = ['.intel_syntax noprefix', '.text']
        code = Code()
        for width, register, size in ((32, 'ymm', 'YMMWORD'), (16, 'xmm', 'XMMWORD')):
            for r in (1, 2):
                lines.append(f'vmovdqu {register}{r}, {size} PTR [rdx]')
                _memory(code, width, 0x6f, r, 0, 'rdx')
            for r in (1, 2):
                lines.append(f'vmovdqu {size} PTR [rdi], {register}{r}')
                _memory(code, width, 0x7f, r, 0, 'rdi')
        for width, size, suffix in ((8, 'QWORD', ''), (4, 'DWORD', 'd'), (2, 'WORD', 'w')):
            for r in (9, 11):
                lines.append((f'movzx r{r}, WORD PTR [rdx]' if width == 2
                              else f'mov r{r}{suffix}, {size} PTR [rdx]'))
                _copy_word(code, width, r)
            for r in (9, 11):
                lines.append(f'mov {size} PTR [rdi], r{r}{suffix}')
                _copy_word(code, width, r, store=True)
        lines += ['movzx r9, BYTE PTR [rdx]', 'mov BYTE PTR [rdi], r9b']
        _copy_word(code, 1, 9)
        _copy_word(code, 1, 9, store=True)
        source = self.root / 'endpoint-encoding.s'
        obj, binary = source.with_suffix('.o'), source.with_suffix('.bin')
        source.write_text('\n'.join(lines) + '\n')
        assembled = subprocess.run(['as', '--64', str(source), '-o', str(obj)], capture_output=True, text=True, timeout=10)
        self.assertEqual(assembled.returncode, 0, assembled.stderr)
        copied = subprocess.run(['objcopy', '-O', 'binary', '-j', '.text', str(obj), str(binary)],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(copied.returncode, 0, copied.stderr)
        self.assertEqual(code.finalize()[0], binary.read_bytes())


if __name__ == '__main__':
    unittest.main()
