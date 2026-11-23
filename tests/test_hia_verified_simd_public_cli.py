"""Drive the installed hia command, its atomic publication, and the independent supplied-artifact verifier."""
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import resource
import signal
import struct
import subprocess
from tempfile import TemporaryDirectory
import unittest

from hepta.hia_scalar_reference_native import sealed_reference_bytes
from hepta.hia_verified_simd import emit_verified_simd, simd_kernel_program

CLI = os.environ.get('HEPTA_HIA_TEST_INSTALLED_SIMD_CLI')


@unittest.skipUnless(CLI, 'requires a source-built installed HIA command with its verifier')
class PublicSIMDTests(unittest.TestCase):
    def test_public_sse2_build_execution_and_independent_proof(self):
        cli = Path(CLI).resolve()
        with TemporaryDirectory() as temp:
            root = Path(temp)
            for index, kind in enumerate(('sum_u8', 'all_zero_u8', 'copy_u8'), 1):
                with self.subTest(kernel=kind):
                    core = simd_kernel_program(kind, 'byte_kernel')
                    raw = core.canonical_bytes
                    source = root / (kind + '.hepta')
                    source.write_bytes(raw)
                    output = root / (kind + '.so')
                    result = subprocess.run([cli, 'build', source, '-o', output, '--backend','auto',
                                             '--kind','shared','--target-isa','sse2'], env={'PATH':''},
                                            capture_output=True, timeout=90, check=True)
                    self.assertFalse(result.stderr)
                    report = json.loads(result.stdout)
                    linked = output.read_bytes()
                    obj = emit_verified_simd(core, isa='sse2').object_bytes
                    for name, blob in [('artifact_sha256',linked),('object_sha256',obj)]:
                        self.assertEqual(report[name],sha256(blob).hexdigest())
                    self.assertEqual(report['selected_strategy'],'simd')
                    self.assertEqual(report['simd_isa'],'sse2')
                    self.assertTrue(report['validation']['complete'])
                    verifier = cli.parent / 'hia-safe-core-prove'
                    def prove(core_bytes, object_bytes, final_bytes):
                        frame = struct.pack('<8s5Q', b'HIASP001',1,10000,len(core_bytes),len(object_bytes),len(final_bytes))
                        with sealed_reference_bytes(frame,core_bytes,object_bytes,final_bytes) as fd:
                            os.lseek(fd,0,os.SEEK_SET)
                            return subprocess.run([verifier],stdin=fd,env={'PATH':''},capture_output=True,timeout=20)
                    proof = prove(raw,obj,linked)
                    self.assertEqual((proof.returncode,proof.stdout[:8]),(0,b'HIASIMR1'))
                    offset = struct.unpack_from('<Q',proof.stdout,48)[0]
                    self.assertEqual(struct.unpack_from('<4Q',proof.stdout,16),(1,index,16,4))
                    pos = obj.index(bytes.fromhex('4983ea40'),64) + 3
                    altered = bytearray(obj)
                    altered[pos] = 63
                    changed = bytearray(linked)
                    changed[offset+pos-64] = 63
                    refusal = prove(raw,bytes(altered),bytes(changed))
                    self.assertNotEqual(refusal.returncode,0)
                    self.assertFalse(refusal.stdout)
                    entry = ctypes.CDLL(str(output),mode=os.RTLD_NOW).byte_kernel
                    pair = [ctypes.c_void_p,ctypes.c_uint64]
                    entry.argtypes = (pair*2 if index==3 else pair) + [ctypes.c_uint64]
                    entry.restype = ctypes.c_uint64
                    for n in (0,1,15,16,17,63,64,65,127,128,129):
                        for data in (bytes(n),bytes((i*19+1)%256 for i in range(n))):
                            src = ctypes.create_string_buffer(data)
                            dst = ctypes.create_string_buffer(max(n,1))
                            if index == 3:
                                self.assertEqual(entry(dst,n,src,n,n),n)
                                self.assertEqual(bytes(dst)[:n],data)
                            else:
                                self.assertEqual(entry(src,n,n),sum(data) if index==1 else int(not any(data)))
                    src=ctypes.create_string_buffer(8)
                    calls=[(src,2,3)] if index<3 else [(src,2,src,8,3),(src,8,src,8,4)]
                    for args in calls:
                        pid=os.fork()
                        if pid == 0:
                            resource.setrlimit(resource.RLIMIT_CORE,(0,0))
                            entry(*args)
                            os._exit(0)
                        _,status=os.waitpid(pid,0)
                        self.assertTrue(os.WIFSIGNALED(status))
                        self.assertEqual(os.WTERMSIG(status),signal.SIGABRT)
