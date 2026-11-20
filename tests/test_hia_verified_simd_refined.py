"""Native bounded reductions and one-byte copy tails after final proof/CPU gating."""
from __future__ import annotations

import ctypes
from hashlib import sha256
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.hia_machine_x64 import Code
from hepta.hia_verified_cpu import VerifiedCPURejected, probe_host_isa
from hepta.hia_verified_kernel import build_verified_kernel
from hepta.hia_verified_kernel_load import load_verified_simd_kernel
from hepta.hia_verified_simd import emit_verified_simd, simd_kernel_program
from hepta.hia_verified_simd_check import VerifiedSIMDRejected
from hepta.hia_verified_simd_wide import _memory, _register, _reduce_word_load
from tests import test_hia_verified_simd as legacy
from tests import test_hia_verified_simd_copy_tail as endpoint_native
from tests.test_hia_verified_simd_wide import REQUIREMENTS


# Filled with the hashes recorded before this profile was introduced. These
# identify complete legacy objects, including their control flow and symbols.
HISTORICAL_PROFILES = (
    ('sse2', 1, 'sum_u8', None, 'e6c7456be5991f370128a086e584c9bec78060619ebf9ed0650efe6607ba82fb', '64ec37e8f63b6de960ecc8da9c950e2a0d1d351ac2892bb381b949ccf181ee1b'),
    ('sse2', 1, 'all_zero_u8', None, '917c83b554c287a6d384e2aec78d9d1cae49b1236d80658f8dac64ce958c3035', '815450d56b391b5e067a259057e32b80685608e0d3235fbdcc8d41207108e338'),
    ('sse2', 1, 'copy_u8', None, 'a3dcf1325edd28025928b74219dde97f629213dcf21544032d32cec2f9826409', '0868165cefcf918d8a1aa7c538a8158c67e2e0b37162467d4e5c0b6c24bd75cc'),
    ('sse2', 4, 'sum_u8', None, '76868fd9b06108cb6ff531e03dc085c7ac5c1616787e6a2068c78c2c9c19430a', '9c49db9ea7bb953d766912ab3ec868c6ff7802ce1fa2d6bf5b065153beb98496'),
    ('sse2', 4, 'all_zero_u8', None, 'b8dd98bea7760fb5c6f75394bf13067eac2200ffab4e52cd5de5a25025f72982', '0c403159d6a8ac958b8042aaeea853980a0f65d296777dbcf9bee23fc859f631'),
    ('sse2', 4, 'copy_u8', None, '2977ff888c5ccb7da1ee32111ec09b8dec8eef52d55c88b6217d2b0aa8859b2e', '3dbb472f6be7ce54a9a7214ed1ae03bcc5051b6b9cc2dd95300e72f58dbd308d'),
    ('avx2', 4, 'sum_u8', None, 'ced3c6bac6366826f0921a77214b2992fc3705a36a4a96a34644d5a776540fe0', '72259935c01ef4ead27f52dfac0a7a6d991eafc6b7b14ebe7cd19da76fa97da6'),
    ('avx2', 4, 'all_zero_u8', None, '511ec559448c060f188b948187dfb74733f607c60d2bcf2f536bc78c3d827f69', '766e66eb25e32637ac170cd544e0b7701e6461bffe9f4e08fb44b12b165c1f4e'),
    ('avx2', 4, 'copy_u8', 'byte', '04514f6bea6d407b5c69436f7d914ef313f2fca13fb63b4d606fdce6c02e20f4', '43b5477c865f22ecd0673b5ab3874ef5a95928bc61ccecd2900ab1c98840934c'),
    ('avx2', 4, 'copy_u8', 'endpoints', '67db2ff0aa7153d816967d7f5c358159e2a248c9851472d6a041c408da4539db', '5826160d7e0c3d2d064b4c3ded55ca356a530b259ac38d2df0970004c293e02c'),
    ('avx512', 4, 'sum_u8', None, '5ff5c912988536a0b775957b1af9cbc64e05f8f52b6c743a13329cd9aa74ba3e', '346e8c068d10ff26c5ff78ed5d343c7ecf4b7276e1d9a5701a1c419f1baa0932'),
    ('avx512', 4, 'all_zero_u8', None, '7e324cb970caa280c86a909890fc68b57d1a21033b6e9c25bc7d16029b23e173', 'aa4f17833b69b75737e00bdaa12ec16aa3ca7bfd58c6bee7315f9371551ca029'),
    ('avx512', 4, 'copy_u8', 'byte', '67803976bf2c7ea29de6589d59119ca3eafa134c6af923a2a8e859e264955d20', '2298cfba5e3dba6fbba3a51e614efcf255451815013b02afe242e7d339de2d6c'),
    ('avx512', 4, 'copy_u8', 'endpoints', '506fedb3c6a52b786e274921e3d58fc3e17fde6bfe6ddab8e14a13c106a1901f', '0ebf73944c685fed653ff08589915f2c5d5b04a0de02f7160095dab146ae2302'),
)


@unittest.skipUnless(legacy.AVAILABLE, 'Linux x86-64, GNU ld and pinned Z3 are required')
class VerifiedRefinedNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='hia-refined-native-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        features = set(probe_host_isa()['common_features'])
        cls.images, cls.refusals = {}, {}
        for (isa, kind), required in REQUIREMENTS.items():
            core = simd_kernel_program(kind)
            image = emit_verified_simd(core, isa=isa)
            path = cls.root / (isa + '-' + kind + '.so')
            if not required <= features:
                try:
                    build_verified_kernel(core, path, strategy='simd', simd_isa=isa)
                except VerifiedCPURejected as exc:
                    if path.exists() or 'does not enable' not in str(exc):
                        raise AssertionError('unsupported refined image was not refused before publication') from exc
                    cls.refusals[isa, kind] = str(exc)
                else:
                    raise AssertionError('unsupported refined image was published')
                continue
            build = build_verified_kernel(core, path, strategy='simd', simd_isa=isa)
            loaded = load_verified_simd_kernel(core, image.object_bytes, path.read_bytes())
            cls.images[isa, kind] = (core, image, path, build, loaded)
        print('Refined native coverage: ' + str(len(cls.images)) + ' proved/admitted images; ' +
              str(len(cls.refusals)) + ' unsupported images refused')

    def test_new_defaults_are_proved_bound_and_admitted_before_execution(self):
        self.assertEqual(set(self.images) | set(self.refusals), set(REQUIREMENTS))
        for (isa, kind), (_, image, path, build, loaded) in self.images.items():
            with self.subTest(isa=isa, kind=kind):
                copy_tail = 'endpoints-fast' if kind == 'copy_u8' else None
                reduce_tail = None if kind == 'copy_u8' else 'bounded'
                self.assertEqual((image.copy_tail, image.reduce_tail), (copy_tail, reduce_tail))
                self.assertEqual((build['simd_copy_tail'], build['simd_reduce_tail']), (copy_tail, reduce_tail))
                proof = build['validation']
                self.assertTrue(proof['ok'] and proof['complete'])
                self.assertEqual(proof['subject']['object_sha256'], sha256(image.object_bytes).hexdigest())
                self.assertEqual(proof['subject']['final_image_sha256'], sha256(path.read_bytes()).hexdigest())
                self.assertEqual(set(proof['required_cpu_features']), REQUIREMENTS[isa, kind])
                self.assertTrue(loaded.mapping_admission['sealed_image_and_loaded_symbol_bound'])
                self.assertEqual(build['runtime_solver_calls'], 0)
                if kind == 'copy_u8':
                    self.assertEqual(loaded.function(None, 0, None, 0, 0), 0)
                else:
                    self.assertEqual(loaded.function(None, 0, 0), int(kind == 'all_zero_u8'))

    def test_bounded_reductions_cover_all_short_lengths_offsets_and_large_ranges(self):
        lengths = list(range(514)) + [1023, 1024, 1025, 4095, 4096, 4097, 65535, 65536]
        offsets = (0, 1, 7, 15, 16, 31, 32, 63)
        for isa in ('avx2', 'avx512'):
            sums, zeros = self.images.get((isa, 'sum_u8')), self.images.get((isa, 'all_zero_u8'))
            if sums is None or zeros is None:
                self.assertTrue((isa, 'sum_u8') in self.refusals or (isa, 'all_zero_u8') in self.refusals)
                continue
            for n in lengths:
                for values in (bytes((i * 173 + 29) & 255 for i in range(n)), b'\xff' * n, b'\0' * n):
                    expected_sum, expected_zero = sum(values), int(not any(values))
                    for offset in offsets:
                        original = b'L' * offset + values + b'R' * 65
                        memory = ctypes.create_string_buffer(original)
                        address = ctypes.addressof(memory) + offset
                        self.assertEqual(sums[4].function(address, n + 65, n), expected_sum, (isa, n, offset))
                        self.assertEqual(zeros[4].function(address, n + 65, n), expected_zero, (isa, n, offset))
                        self.assertEqual(memory.raw[:len(original)], original, (isa, n, offset))

    def test_every_byte_position_contributes_to_sum_and_zero_in_short_ranges(self):
        lengths = list(range(1, 130)) + [255, 256, 257, 511, 512, 513]
        for isa in ('avx2', 'avx512'):
            sums, zeros = self.images.get((isa, 'sum_u8')), self.images.get((isa, 'all_zero_u8'))
            if sums is None or zeros is None:
                continue
            for n in lengths:
                memory = (ctypes.c_uint8 * n)()
                for index in range(n):
                    for value in (1, 128, 255):
                        memory[index] = value
                        self.assertEqual(sums[4].function(memory, n, n), value, (isa, n, index, value))
                        self.assertEqual(zeros[4].function(memory, n, n), 0, (isa, n, index, value))
                    memory[index] = 0
                self.assertEqual(zeros[4].function(memory, n, n), 1)

    @unittest.skipUnless(shutil.which('cc'), 'C compiler required for exact reduction guard pages')
    def test_bounded_word_reads_respect_start_and_end_guard_pages(self):
        source = self.root / 'bounded-guard-pages.c'
        executable = source.with_suffix('')
        source.write_text(r'''
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>
typedef uint64_t (*reduce_t)(const uint8_t*,uint64_t,uint64_t);
int main(int argc,char**argv){
  struct rlimit limit={0,0};setrlimit(RLIMIT_CORE,&limit);
  if(argc!=3)return 1;
  size_t page=(size_t)sysconf(_SC_PAGESIZE);if(page!=4096)return 2;
  void* sl=dlopen(argv[1],RTLD_NOW);void* zl=dlopen(argv[2],RTLD_NOW);
  if(!sl||!zl)return 3;
  reduce_t sum=(reduce_t)dlsym(sl,"calculate"),zero=(reduce_t)dlsym(zl,"calculate");
  if(!sum||!zero)return 4;
  uint8_t* memory=mmap(0,page*3,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
  if(memory==MAP_FAILED||mprotect(memory+page,page,PROT_READ|PROT_WRITE))return 5;
  for(size_t n=1;n<=page;n++)for(unsigned end=0;end<2;end++){
    memset(memory+page,0xa5,page);
    size_t offset=end?page-n:0;uint8_t* p=memory+page+offset;uint64_t expected=0;
    for(size_t i=0;i<n;i++){p[i]=(uint8_t)(i*37+11);expected+=p[i];}
    if(sum(p,n,n)!=expected||zero(p,n,n)!=0)return 6;
    for(size_t i=0;i<page;i++){
      uint8_t wanted=i<offset||i>=offset+n?0xa5:(uint8_t)((i-offset)*37+11);
      if(memory[page+i]!=wanted)return 7;
    }
    memset(p,0,n);if(zero(p,n,n)!=1||sum(p,n,n)!=0)return 8;
    p[n-1]=255;if(zero(p,n,n)!=0||sum(p,n,n)!=255)return 9;
  }
  puts("4096 lengths x 2 exact guard placements passed");return 0;
}
''')
        built = subprocess.run(['cc', '-O2', '-Wall', '-Wextra', str(source), '-ldl', '-o', str(executable)],
                               capture_output=True, text=True, timeout=30)
        self.assertEqual(built.returncode, 0, built.stderr)
        for isa in ('avx2', 'avx512'):
            sums, zeros = self.images.get((isa, 'sum_u8')), self.images.get((isa, 'all_zero_u8'))
            if sums is None or zeros is None:
                continue
            result = subprocess.run([str(executable), str(sums[2]), str(zeros[2])],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, (isa, result.stdout, result.stderr))
            self.assertEqual(result.stdout.strip(), '4096 lengths x 2 exact guard placements passed')

    def test_fast_copy_effects_adjacent_ranges_and_both_guard_ends(self):
        self.cases = {isa: values[1:] for (isa, kind), values in self.images.items() if kind == 'copy_u8'}
        endpoint_native.VerifiedCopyEndpointNativeTests.test_all_short_suffixes_and_asymmetric_alignments_preserve_exact_effects(self)
        endpoint_native.VerifiedCopyEndpointNativeTests.test_adjacent_nonoverlapping_ranges_work_in_both_address_orders(self)
        if shutil.which('cc'):
            endpoint_native.VerifiedCopyEndpointNativeTests.test_guard_pages_cover_both_ends_of_every_short_and_vector_range(self)

    def test_invalid_ranges_abort_before_access_in_every_new_default(self):
        for isa in ('avx2', 'avx512'):
            cases = {kind: (values[0], values[1], values[2], values[3]['validation'])
                     for (target, kind), values in self.images.items() if target == isa}
            if len(cases) == 3:
                self.cases = cases
                legacy.VerifiedSIMDTests.test_invalid_native_ranges_abort_before_touching_memory(self)

    def test_all_fourteen_historical_profiles_retain_their_complete_bytes(self):
        self.assertEqual(len(HISTORICAL_PROFILES), 14)
        for isa, unroll, kind, copy_tail, text_hash, object_hash in HISTORICAL_PROFILES:
            with self.subTest(isa=isa, unroll=unroll, kind=kind, copy_tail=copy_tail):
                image = emit_verified_simd(simd_kernel_program(kind), isa=isa, unroll=unroll,
                                           copy_tail=copy_tail, reduce_tail='byte')
                self.assertEqual(sha256(image.text_bytes).hexdigest(), text_hash)
                self.assertEqual(sha256(image.object_bytes).hexdigest(), object_hash)

    def test_invalid_refinements_and_nonwide_bounded_targets_are_rejected(self):
        for value in (True, False, 0, 1, '', 'words', 'endpoints', [], {}):
            with self.subTest(value=value), self.assertRaises(VerifiedSIMDRejected):
                emit_verified_simd(simd_kernel_program('sum_u8'), isa='avx2', reduce_tail=value)
        for isa, kind in (('sse2', 'sum_u8'), ('sse2', 'all_zero_u8'), ('sse2', 'copy_u8'),
                          ('avx2', 'copy_u8'), ('avx512', 'copy_u8')):
            with self.subTest(isa=isa, kind=kind), self.assertRaises(VerifiedSIMDRejected):
                emit_verified_simd(simd_kernel_program(kind), isa=isa, reduce_tail='bounded')
        for kind in ('sum_u8', 'all_zero_u8'):
            with self.assertRaises(VerifiedSIMDRejected):
                emit_verified_simd(simd_kernel_program(kind), isa='avx2', copy_tail='endpoints-fast')

    @unittest.skipUnless(shutil.which('as') and shutil.which('objcopy'), 'GNU as/objcopy required for encoder cross-check')
    def test_new_instruction_bytes_match_independent_system_assembler(self):
        code = Code()
        lines = ['.intel_syntax noprefix', '.text']
        for width, instruction in ((8, 'mov r9,QWORD PTR [rdi]'), (4, 'mov r9d,DWORD PTR [rdi]'),
                                   (2, 'movzx r9,WORD PTR [rdi]'), (1, 'movzx r9,BYTE PTR [rdi]')):
            _reduce_word_load(code, width)
            lines.append(instruction)
        code.emit(bytes.fromhex('c4c1f96ec9'))
        lines.append('vmovq xmm1,r9')
        _register(code, 16, 0xf6, 1, 2, 1)
        lines.append('vpsadbw xmm1,xmm2,xmm1')
        code.emit(bytes.fromhex('c4c1f97ec9'))
        lines.append('vmovq r9,xmm1')
        _memory(code, 16, 0xf6, 1, 2, 'rdi')
        lines.append('vpsadbw xmm1,xmm2,XMMWORD PTR [rdi]')
        _memory(code, 16, 0xeb, 0, 0, 'rdi')
        lines.append('vpor xmm0,xmm0,XMMWORD PTR [rdi]')
        for register in (0, 2):
            _register(code, 16, 0xef, register, register, register)
            lines.append(f'vpxor xmm{register},xmm{register},xmm{register}')
        source = self.root / 'bounded-encoding.s'
        obj, binary = source.with_suffix('.o'), source.with_suffix('.bin')
        source.write_text('\n'.join(lines) + '\n')
        assembled = subprocess.run(['as', '--64', str(source), '-o', str(obj)],
                                   capture_output=True, text=True, timeout=10)
        self.assertEqual(assembled.returncode, 0, assembled.stderr)
        copied = subprocess.run(['objcopy', '-O', 'binary', '-j', '.text', str(obj), str(binary)],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(copied.returncode, 0, copied.stderr)
        self.assertEqual(code.finalize()[0], binary.read_bytes())


if __name__ == '__main__':
    unittest.main()
