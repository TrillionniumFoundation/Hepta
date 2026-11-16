"""HIA SHA-256: independent VM first, real selfhost generations, byte oracles."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
import ctypes
import json
import os
from hashlib import sha256
from pathlib import Path
import random
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_sha256_native import NativeSha256, installed_hasher, payload_sha256
from tools.generate_hia_sha256 import document
from tests.test_hia_json_decode_native import vm_arena

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'examples/hia_bootstrap/sha256.hepta'
VECTORS=(
    (b'', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
    (b'abc','ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'),
    (b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq','248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1'))


def reference(wire):
    return vm_arena(wire,source_path=SOURCE,sizes=(32,1088))


class Sha256HiaSourceTests(unittest.TestCase):
    def test_generated_source_and_independent_VM_FIPS_vectors(self):
        from hepta.hia_agent_assembly import render_assembly,assemble_program
        self.assertEqual(SOURCE.read_text(),render_assembly(document()))
        self.assertEqual(len(assemble_program(SOURCE.read_bytes()).as_dict()['functions']),5)
        for wire,expected in VECTORS:
            code,output=reference(wire)
            self.assertEqual(code,32)
            self.assertEqual(output.hex(),expected)


class Sha256HiaNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Execute in the independent Core VM before creating ANY native seed.
        code,value=reference(b'abc')
        assert code==32 and value.hex()==VECTORS[1][1]
        from tools.qualify_hia_selfhost import build_seed,compile_stage
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        cls.temporary=tempfile.TemporaryDirectory(prefix='hia-sha256-native-')
        folder=Path(cls.temporary.name)
        seed,_=build_seed(folder)
        source=(ROOT/'examples/hia_bootstrap/selfhost.hepta').read_bytes()
        first,_=compile_stage(folder,'B1',seed,source,image_format='seed-shared')
        second,_=compile_stage(folder,'B2',first,source)
        assert first.read_bytes()==second.read_bytes()
        image,cls.receipt=compile_stage(folder,'sha256',second,SOURCE.read_bytes())
        # This base is only the existing six-argument RX ABI mapping; no JSON
        # parser/arena is used for SHA-256. It does not attest hash correctness.
        cls.code=NativeHiaJsonImage(image.read_bytes(),sha256(image.read_bytes()).hexdigest())

        cls.manifest=folder/'manifest.json'
        cls.manifest.write_text(json.dumps({'schema':'hepta.hia.sha256-native.v1',
            'source_sha256':sha256(SOURCE.read_bytes()).hexdigest(),'image_path':image.name,
            'image_sha256':sha256(image.read_bytes()).hexdigest(),
            'compiler_sha256':sha256(second.read_bytes()).hexdigest()}))

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def digest(self,wire):
        source=ctypes.create_string_buffer(wire,max(1,len(wire)))
        output=ctypes.create_string_buffer(40)
        output.raw=b'\xa5'*40
        workspace=ctypes.create_string_buffer(1096)
        workspace.raw=b'\x5a'*1096
        code=self.code._entry(source,len(wire),output,32,workspace,1088)
        self.assertEqual(code,32)
        self.assertEqual(output.raw[32:],b'\xa5'*8)
        self.assertEqual(workspace.raw[1088:],b'\x5a'*8)
        self.assertEqual(source.raw[:len(wire)],wire)
        return output.raw[:32]

    def test_FIPS_vectors_padding_boundaries_and_binary_data(self):
        for wire,expected in VECTORS:
            self.assertEqual(self.digest(wire).hex(),expected)
        self.assertEqual(self.digest(b'a'*1000000).hex(),
            'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0')
        for size in (0,1,7,31,32,54,55,56,57,63,64,65,119,120,127,128,129,255,256,257,1024):
            wire=bytes((i*137+29)&255 for i in range(size))
            self.assertEqual(self.digest(wire),sha256(wire).digest())
        self.assertEqual(self.receipt['forbidden_compiler_modules_loaded'],[])

    def test_two_thousand_random_inputs_and_payload_bit_mutations(self):
        rng=random.Random(0x256f1)
        for _ in range(2000):
            wire=rng.randbytes(rng.randrange(513))
            self.assertEqual(self.digest(wire),sha256(wire).digest())
        base=rng.randbytes(128)
        original=self.digest(base)
        for bit in range(128*8):
            wire=bytearray(base);wire[bit>>3]^=1<<(bit&7)
            value=self.digest(bytes(wire))
            self.assertEqual(value,sha256(wire).digest())
            self.assertNotEqual(value,original)

    def test_actual_native_hash_does_not_call_foreign_hashlib(self):
        with patch('hashlib.sha256',side_effect=AssertionError('foreign hash call')):
            self.assertEqual(self.digest(b'abc').hex(),VECTORS[1][1])

    def test_private_workspace_concurrency_and_max_input(self):
        wires=[bytes([i])*((i*53)%513) for i in range(64)]
        with ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(list(pool.map(self.digest,wires)),[sha256(w).digest() for w in wires])
        wire=b'\x00\x80\xff.'*((8<<20)>>2)
        self.assertEqual(self.digest(wire),sha256(wire).digest())

    def test_ABI_profile_refuses_before_any_output_write(self):
        source=ctypes.create_string_buffer(b'abc')
        for source_size,output_size,workspace_size in ((0,31,1088),(0,32,1087),((8<<20)+1,32,1088)):
            output=ctypes.create_string_buffer(b'\xa5'*40,40)
            workspace=ctypes.create_string_buffer(b'\x5a'*1096,1096)
            self.assertEqual(self.code._entry(source,source_size,output,output_size,workspace,workspace_size),0xfffffffd)
            self.assertEqual(output.raw,b'\xa5'*40)
            self.assertEqual(workspace.raw,b'\x5a'*1096)

    def test_selected_Core_content_hashes_use_HIA_without_foreign_payload_hash(self):
        from hepta.hia_program import verify_program
        from tests.test_hia_program_tools import scalar_program
        checked=verify_program(scalar_program())
        expected=sha256(checked.canonical_bytes).hexdigest()
        installed_hasher(str(self.manifest))
        with patch.dict('os.environ',{'HEPTA_HIA_SHA256_MANIFEST':str(self.manifest)}):
            with patch('hepta.hia_sha256_native._foreign_sha256',side_effect=AssertionError('foreign payload hash')):
                self.assertEqual(checked.sha256,expected)
                self.assertEqual(checked.input_sha256,expected)
                self.assertEqual(payload_sha256(b'abc').hex(),VECTORS[1][1])
        # The Core checker itself is still required and retains its authority.
        invalid=scalar_program();invalid['functions'][0]['blocks'][0]['term']['values']=['missing']
        with patch.dict('os.environ',{'HEPTA_HIA_SHA256_MANIFEST':str(self.manifest)}),self.assertRaises(ValueError):
            verify_program(invalid)

    def test_manifest_identity_and_selected_errors_do_not_fall_back(self):
        from hepta import hia_sha256_native as native
        original=installed_hasher(str(self.manifest))
        self.assertEqual(original.digest(b'abc').hex(),VECTORS[1][1])
        bad=self.manifest.with_name('wrong-source.hepta');bad.write_bytes(b'changed')
        with patch.object(native,'SOURCE',bad),self.assertRaisesRegex(ValueError,'source identity'):
            installed_hasher(str(self.manifest))
        self.assertIs(installed_hasher(str(self.manifest)),original)
        with patch.dict('os.environ',{'HEPTA_HIA_SHA256_MANIFEST':'/missing/manifest'}):
            with self.assertRaises(FileNotFoundError):payload_sha256(b'abc')
        with patch.dict(os.environ):
            os.environ.pop('HEPTA_HIA_SHA256_MANIFEST', None)
            self.assertEqual(payload_sha256(memoryview(b'abc')).hex(),VECTORS[1][1])
        with self.assertRaises(ValueError):original.digest(bytearray(b'abc'))
        with self.assertRaises(ValueError):NativeSha256(b'code','0'*64)
