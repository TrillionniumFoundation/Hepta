"""Qualify the native wide object producer and independent AVX2 machine grammar."""
import os
from pathlib import Path
import struct
import subprocess
from tempfile import TemporaryDirectory
import unittest

from hepta.hia_scalar_reference_native import sealed_reference_bytes
from hepta.hia_verified_simd import emit_verified_simd, simd_kernel_program
from hepta.hia_verified_simd_check import decode_simd, validate_verified_simd_artifact
from tools.qualify_hia_selfhost import compile_stage, invoke

ROOT = Path(__file__).resolve().parents[1]
COMPILER = os.environ.get('HEPTA_HIA_SELFHOST_TEST_COMPILER')
BINDER = os.environ.get('HEPTA_HIA_TEST_ELF_BINDER')


@unittest.skipUnless(COMPILER and BINDER, 'requires the cold compiler and source-built HIA ELF binder')
class WideByteKernelTests(unittest.TestCase):
    def test_machine_parity_and_independent_avx2_decode(self):
        with TemporaryDirectory() as name:
            root = Path(name)

            def compile_image(name):
                source = ROOT / 'examples/hia_bootstrap' / (name + '.hepta')
                return compile_stage(root,name,Path(COMPILER),source.read_bytes())[0]

            def call(tag, image, frame, output=2048, workspace=2048):
                status, raw = invoke(root,tag,image,frame,capacity=output,workspace_size=workspace)
                self.assertEqual(status['status'],'returned')
                self.assertLessEqual(status['core_u32'],output)
                return raw[:status['core_u32']]

            def bind(obj, final, symbol):
                hdr = struct.pack('<8sQQQ256s',b'HIAEBND1',len(obj),len(final),len(symbol),symbol)
                with sealed_reference_bytes(hdr,obj,final) as fd:
                    os.lseek(fd,0,os.SEEK_SET)
                    result = subprocess.run([BINDER],stdin=fd,env={'PATH':''},capture_output=True,check=True)
                self.assertEqual(result.stdout[:8],b'HIAEBNR1')
                return result.stdout

            producer = compile_image('verified_simd_sse2_object')
            avx = (7, 0x1c000000, 6, 1 << 5)
            wide = (7, 0x1c000000, 0xe6, (1 << 5) | (1 << 16) | (1 << 30))
            baseline = (7, 0x1c000000, 2, (1 << 5) | (1 << 16) | (1 << 30))
            for index,(reads,wanted) in enumerate([([wide],3),([avx,wide],2),([wide,baseline],1),
                                                    ([(7,0,0xe6,wide[3])],1),([],None)]):
                hdr = struct.pack('<8sQ',b'HIAICPU1',len(reads))
                frame = hdr + b''.join(struct.pack('<4Q',*cpu) for cpu in reads)
                expected = struct.pack('<Q',wanted) if wanted else b''
                self.assertEqual(call('target-'+str(index),producer,frame,8,8),expected)
            checker = compile_image('verified_simd_avx2_check')
            linker = compile_image('elf_verified_linker')
            for shape,kind in enumerate(('sum_u8','all_zero_u8','copy_u8'),1):
                symbol = b'qualified_byte_' + str(shape).encode()
                core = simd_kernel_program(kind,symbol.decode())
                for isa,target in [(1,'sse2'),(2,'avx2'),(3,'avx512')]:
                    with self.subTest(kind=kind,isa=target):
                        tag = kind + '-' + target
                        intent = struct.pack('<8sQQ',b'HIASIMC1',shape,len(symbol)) + symbol + struct.pack('<Q',isa)
                        obj = call(tag+'-object',producer,intent)
                        self.assertEqual(obj,emit_verified_simd(core,isa=target).object_bytes)
                        final = call(tag+'-final',linker,obj,90112,512)
                        self.assertTrue(validate_verified_simd_artifact(core,obj,final)['ok'])
                        bound = bind(obj,final,symbol)
                        def verify(suffix,receipt,subject=shape):
                            return call(tag+'-'+suffix,checker,struct.pack('<Q',subject)+receipt,32)
                        if target != 'avx2':
                            self.assertEqual(verify('cross-isa',bound),b'')
                            continue
                        offset, _, span = struct.unpack_from('<3Q',bound,8)
                        self.assertEqual(verify('accept',bound),struct.pack('<8s3Q',b'HIASIMV1',shape,2,span))
                        self.assertEqual(verify('wrong-source',bound,1+(shape%3)),b'')
                        self.assertEqual(verify('truncated',bound[:-1]),b'')
                        text = bound[80:80+span]
                        rows = decode_simd(text)
                        vector = next(r for r in rows if r.op in ('vload','vpor_mem','vpsadbw_mem') and r.args[0] == 256)
                        word = next(r for r in rows if r.op == 'copy_load')
                        edits = {
                            'guard':next(r.pc+1 for r in rows if r.op == 'jcc'),
                            'jump':next(r.pc+1 for r in rows if r.op == 'jmp'),
                            'count':text.index(bytes.fromhex('4981ea80000000'))+3,
                            'width':vector.pc+1,
                            'opcode':vector.pc+2,
                            'register':vector.pc+3,
                            'word-base':word.pc+word.size-1,
                        }
                        for label,where in edits.items():
                            bad_obj = bytearray(obj)
                            bad_elf = bytearray(final)
                            bad_obj[64+where] ^= 1
                            bad_elf[offset+where] ^= 1
                            self.assertEqual(verify(label,bind(bytes(bad_obj),bytes(bad_elf),symbol)),b'',label)
