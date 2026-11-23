"""Run installed explicit wide and native builds and recheck their public proof."""
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import subprocess
from tempfile import TemporaryDirectory
import unittest

from hepta.hia_scalar_reference_native import sealed_reference_bytes
from hepta.hia_verified_cpu import resolve_target_isa, probe_host_isa
from hepta.hia_verified_simd import emit_verified_simd, simd_kernel_program
from hepta.hia_verified_simd_check import validate_verified_simd_artifact

CLI = os.environ.get('HEPTA_HIA_TEST_INSTALLED_SIMD_CLI')
IDS = {'sse2':1,'avx2':2,'avx512':3}


@unittest.skipUnless(CLI, 'requires the installed HIA command and independent supplied verifier')
class PublicWideSIMDTests(unittest.TestCase):
    def test_wide_and_native_targets(self):
        cli = Path(CLI).resolve()
        native = resolve_target_isa('native')
        host = probe_host_isa()
        with TemporaryDirectory() as td:
            root = Path(td)
            for shape,kind in enumerate(('sum_u8','all_zero_u8','copy_u8'),1):
                core = simd_kernel_program(kind,'public_byte_range')
                source = root / (kind+'.hepta')
                source.write_bytes(core.canonical_bytes)
                for requested in ('avx2','avx512','native'):
                    with self.subTest(kind=kind,requested=requested):
                        isa = native if requested == 'native' else requested
                        out = root / (kind+'-'+requested+'.so')
                        result = subprocess.run([cli,'build',source,'-o',out,'--kind','shared','--backend','auto',
                                                 '--target-isa',requested],capture_output=True,env={'PATH':''},timeout=90)
                        self.assertEqual((result.returncode,result.stderr),(0,b''))
                        row = json.loads(result.stdout)
                        elf = out.read_bytes()
                        obj = emit_verified_simd(core,isa=isa).object_bytes
                        self.assertEqual((row['simd_isa'],row['selected_strategy']),(isa,'simd'))
                        self.assertEqual(row['artifact_sha256'],sha256(elf).hexdigest())
                        self.assertEqual(row['object_sha256'],sha256(obj).hexdigest())
                        self.assertEqual(row['simd_copy_tail'],('byte' if isa == 'sse2' else 'endpoints-fast') if shape == 3 else None)
                        self.assertEqual(row['simd_reduce_tail'],None if shape == 3 else ('byte' if isa == 'sse2' else 'bounded'))
                        old = validate_verified_simd_artifact(core,obj,elf)
                        self.assertTrue(old['ok'])
                        for key in ('required_cpu_features','required_xcr0_mask','target_isa'):
                            self.assertEqual(row['validation'][key],old[key])
                        def prove(tag, object_bytes, shared_bytes):
                            raw = core.canonical_bytes
                            hdr = struct.pack('<8s5Q',b'HIASP001',tag,10000,len(raw),len(object_bytes),len(shared_bytes))
                            with sealed_reference_bytes(hdr,raw,object_bytes,shared_bytes) as fd:
                                os.lseek(fd,0,os.SEEK_SET)
                                return subprocess.run([cli.parent/'hia-safe-core-prove'],stdin=fd,env={'PATH':''},capture_output=True,timeout=30)
                        ident = IDS[isa]
                        proof = prove(ident,obj,elf)
                        self.assertEqual(proof.returncode,0)
                        self.assertEqual(struct.unpack_from('<8s5Q',proof.stdout),(b'HIASIMR1',1,ident,shape,8<<ident,4))
                        wrong = prove(1+ident%3,obj,elf)
                        self.assertEqual((wrong.returncode,wrong.stdout),(2,b''))
                        compatible = set(old['required_cpu_features']) <= set(host['common_features'])
                        mask = old['required_xcr0_mask']
                        if compatible and host['common_xcr0'] & mask == mask:
                            f = ctypes.CDLL(str(out),mode=os.RTLD_NOW).public_byte_range
                            pair = [ctypes.c_void_p,ctypes.c_uint64]
                            f.argtypes = (pair*2 if shape == 3 else pair)+[ctypes.c_uint64]
                            f.restype = ctypes.c_uint64
                            for n in (0,1,2,3,4,7,8,15,16,17,31,32,33,63,64,65,127,128,129,255,256,257):
                                for raw in (bytes(n),bytes((i*11+9)%256 for i in range(n))):
                                    buf = ctypes.create_string_buffer(raw)
                                    dst = ctypes.create_string_buffer(max(1,n))
                                    if shape == 3:
                                        self.assertEqual(f(dst,n,buf,n,n),n)
                                        self.assertEqual(dst.raw[:n],raw)
                                    else:
                                        self.assertEqual(f(buf,n,n),sum(raw) if shape==1 else int(not any(raw)))
