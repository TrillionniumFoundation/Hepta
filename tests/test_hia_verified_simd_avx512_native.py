"""Exercise the independent AVX-512 final-text verifier on bound shared objects."""
import ctypes
import os
from pathlib import Path
import struct
import subprocess
from tempfile import TemporaryDirectory
import unittest

from hepta.hia_scalar_reference_native import sealed_reference_bytes
from hepta.hia_verified_cpu import require_host_isa, VerifiedCPURejected
from hepta.hia_verified_simd import emit_verified_simd, simd_kernel_program
from hepta.hia_verified_simd_check import validate_verified_simd_artifact
from tools.qualify_hia_selfhost import compile_stage, invoke

ROOT = Path(__file__).resolve().parents[1]
COMPILER = os.environ.get('HEPTA_HIA_SELFHOST_TEST_COMPILER')
BINDER = os.environ.get('HEPTA_HIA_TEST_ELF_BINDER')


@unittest.skipUnless(COMPILER and BINDER, 'requires a cold HIA compiler and independent ELF binder')
class AVX512TerminalTests(unittest.TestCase):
    def test_independently_bound_text_for_all_three_kernels(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            def compile_source(name):
                raw = (ROOT / 'examples/hia_bootstrap' / (name + '.hepta')).read_bytes()
                return compile_stage(root, name, Path(COMPILER), raw)[0]

            def execute(image, label, inputs, capacity, workspace):
                status, raw = invoke(root, label, image, inputs, capacity=capacity, workspace_size=workspace)
                self.assertEqual(status['status'], 'returned')
                self.assertLessEqual(status['core_u32'], capacity)
                return raw[:status['core_u32']]

            def bind(obj, image):
                header = struct.pack('<8sQQQ256s', b'HIAEBND1', len(obj), len(image), 9, b'calculate')
                with sealed_reference_bytes(header, obj, image) as fd:
                    os.lseek(fd, 0, os.SEEK_SET)
                    result = subprocess.run([BINDER], stdin=fd, env={'PATH':''}, capture_output=True, check=True)
                self.assertEqual(result.stdout[:8], b'HIAEBNR1')
                return result.stdout

            checker = compile_source('verified_simd_avx512_check')
            linker = compile_source('elf_verified_linker')
            for shape, name in enumerate(('sum_u8', 'all_zero_u8', 'copy_u8'), 1):
                with self.subTest(kernel=name):
                    program = simd_kernel_program(name)
                    obj = emit_verified_simd(program, isa='avx512').object_bytes
                    image = execute(linker, name+'-link', obj, 90112, 512)
                    reference = validate_verified_simd_artifact(program, obj, image)
                    self.assertTrue(reference['ok'])
                    receipt = bind(obj, image)
                    def check(label, packet, selected=shape):
                        wire = struct.pack('<Q', selected) + packet
                        return execute(checker, name+'-'+label, wire, 32, 1024)
                    location, _, size = struct.unpack_from('<3Q', receipt, 8)
                    self.assertEqual(check('original', receipt), struct.pack('<8s3Q', b'HIASIMV1', shape, 3, size))
                    self.assertEqual(check('wrong-shape', receipt, shape % 3 + 1), b'')
                    self.assertEqual(check('truncated', receipt[:-1]), b'')
                    self.assertEqual(check('trailing', receipt+b'\0'), b'')
                    text = receipt[80:80+size]
                    # Rebind both object and shared text so the final decoder must
                    # detect the changed condition, vector width, operands or tail.
                    changes = [('unsigned-extent', '0f87', 1), ('backedge', 'e9', 1),
                               ('bound-256', '4981fa00010000', 3), ('step-64', '4983ea40', 3),
                               ('evex-width', '62f1', 3), ('evex-base', '62f1', 5),
                               ('narrow-bound', '4983fa10', 3), ('tail-cleanup', 'c5f877', 2)]
                    specific = ('endpoint-byte-store', '44880f', 2) if shape == 3 else ('fold-lane', '62f3fd483bc101', 6)
                    for label, signature, displacement in (*changes, specific):
                        at = text.index(bytes.fromhex(signature)) + displacement
                        new_obj, new_image = bytearray(obj), bytearray(image)
                        new_obj[64+at] ^= 1
                        new_image[location+at] ^= 1
                        self.assertEqual(check(label, bind(bytes(new_obj), bytes(new_image))), b'')
                    for field in (24, 32, 40, 48):
                        malformed = bytearray(receipt)
                        malformed[80+size+field] ^= 1
                        self.assertEqual(check('relocation-'+str(field), bytes(malformed)), b'')
                    try:
                        require_host_isa(reference['required_cpu_features'], reference['required_xcr0_mask'])
                    except VerifiedCPURejected:
                        continue
                    path = root / (name + '.so')
                    path.write_bytes(image)
                    function = ctypes.CDLL(str(path), mode=os.RTLD_NOW).calculate
                    pair = [ctypes.c_void_p, ctypes.c_uint64]
                    function.argtypes = (pair*2 if shape == 3 else pair) + [ctypes.c_uint64]
                    function.restype = ctypes.c_uint64
                    for n in (0,1,2,3,4,7,8,15,16,17,31,32,33,63,64,65,127,128,255,256,257,513):
                        for value in (bytes(n), bytes((j*7+3)%256 for j in range(n))):
                            src = ctypes.create_string_buffer(value)
                            if shape == 3:
                                dst = ctypes.create_string_buffer(max(n,1))
                                self.assertEqual(function(dst,n,src,n,n), n)
                                self.assertEqual(dst.raw[:n], value)
                            else:
                                self.assertEqual(function(src,n,n), sum(value) if shape == 1 else int(not any(value)))
