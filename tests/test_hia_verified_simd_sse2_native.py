"""Exercise the cold HIA SSE2 object producer and independent final-text checker."""
import ctypes
import os
from pathlib import Path
import struct
import subprocess
from tempfile import TemporaryDirectory
import unittest

from hepta.hia_scalar_reference_native import sealed_reference_bytes
from hepta.hia_verified_simd import emit_verified_simd, simd_kernel_program
from hepta.hia_verified_simd_check import validate_verified_simd_artifact
from tools.qualify_hia_selfhost import compile_stage, invoke

ROOT = Path(__file__).resolve().parents[1]
COMPILER = os.environ.get('HEPTA_HIA_SELFHOST_TEST_COMPILER')
BINDER = os.environ.get('HEPTA_HIA_TEST_ELF_BINDER')


@unittest.skipUnless(COMPILER and BINDER, 'requires cold HIA compiler and independent native ELF binder')
class VerifiedSIMDNativeMachineTests(unittest.TestCase):
    def test_closed_sse2_images_and_rebound_control_flow_refusals(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            def compiled(name):
                source = (ROOT / 'examples/hia_bootstrap' / (name + '.hepta')).read_bytes()
                return compile_stage(root, name, Path(COMPILER), source)[0]

            def execute(label, image, wire, output, work):
                result, raw = invoke(root, label, image, wire, capacity=output, workspace_size=work)
                self.assertEqual(result['status'], 'returned')
                extent = result['core_u32']
                self.assertGreaterEqual(extent, 0)
                self.assertLessEqual(extent, output)
                return raw[:extent]

            def bind(obj, final):
                hdr = struct.pack('<8sQQQ256s', b'HIAEBND1', len(obj), len(final), 9, b'calculate')
                with sealed_reference_bytes(hdr, obj, final) as request:
                    os.lseek(request, 0, os.SEEK_SET)
                    bound = subprocess.run([BINDER], stdin=request, capture_output=True, env={'PATH':''}, check=True)
                self.assertEqual(bound.stdout[:8], b'HIAEBNR1')
                return bound.stdout

            producer = compiled('verified_simd_sse2_object')
            linker = compiled('elf_verified_linker')
            checker = compiled('verified_simd_sse2_check')
            for shape, kind in enumerate(('sum_u8','all_zero_u8','copy_u8'), 1):
                with self.subTest(kernel=kind):
                    frame = struct.pack('<8sQQ9sQ', b'HIASIMC1', shape, 9, b'calculate', 1)
                    obj = execute(kind+'-object', producer, frame, 2048, 2048)
                    core = simd_kernel_program(kind)
                    self.assertEqual(obj, emit_verified_simd(core).object_bytes)
                    so = execute(kind+'-link', linker, obj, 90112, 512)
                    self.assertTrue(validate_verified_simd_artifact(core, obj, so)['ok'])
                    receipt = bind(obj, so)
                    def checked(name, data):
                        return execute(kind+'-'+name, checker, struct.pack('<Q',shape)+data, 64, 2048)
                    self.assertEqual(checked('original',receipt)[:8], b'HIASIMV1')
                    self.assertEqual(checked('truncated',receipt[:-1]), b'')
                    offset, _, span = struct.unpack_from('<3Q',receipt,8)
                    code = receipt[80:80+span]
                    for seq, delta in [('4983ea40',3),('4983fa10',3),('0f87',1),('4983ea40e9',5),('f30f6f',2)]:
                        at=code.index(bytes.fromhex(seq))+delta
                        altered = bytearray(obj)
                        altered[64+at] ^= 1
                        linked = bytearray(so)
                        linked[offset+at] ^= 1
                        self.assertEqual(checked('changed-'+seq,bind(bytes(altered),bytes(linked))),b'')
                    path = root / (kind + '.so')
                    path.write_bytes(so)
                    function = ctypes.CDLL(str(path),mode=os.RTLD_NOW).calculate
                    pair = [ctypes.c_void_p,ctypes.c_uint64]
                    function.argtypes = (pair*2 if shape == 3 else pair)+[ctypes.c_uint64]
                    function.restype = ctypes.c_uint64
                    for n in (0,1,15,16,17,63,64,65,127,128,129):
                        data = bytes((i*7+3)%256 for i in range(n))
                        source = ctypes.create_string_buffer(data)
                        target = ctypes.create_string_buffer(max(n,1))
                        if shape == 3:
                            self.assertEqual(function(target,n,source,n,n),n)
                            self.assertEqual(bytes(target)[:n],data)
                        else:
                            self.assertEqual(function(source,n,n),sum(data) if shape==1 else int(not any(data)))
