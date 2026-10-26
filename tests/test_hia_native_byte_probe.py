"""Actual Clang/ELF execution of a finite externally-specified HIA byte witness."""
import ctypes
from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_hia_resource_trace import fixture
from hepta.hia_native_byte_probe import (
    HIANativeByteProbeRejected, compile_native_byte_trace, _render_native_byte_trace)
from hepta.hia_byte_trace import replay_byte_memory_path


@unittest.skipUnless(shutil.which('clang'), 'real Clang required')
class NativeByteTraceTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory(prefix='hia-native-byte-test-')
        self.addCleanup(self.dir.cleanup)
        self.output = Path(self.dir.name) / 'oracle.so'

    def compile(self, *, inputs=None, actions=None):
        graph, checked = fixture(borrow=True)
        return compile_native_byte_trace(graph, checked, 'f', inputs=inputs or {'p0': True},
                                         actions=actions if actions is not None else (
                                             {'kind': 'alloc', 'bytes': 16},
                                             {'kind': 'read', 'index': 5}), output=self.output)

    def test_real_clang_shared_library_returns_runtime_read_checksum(self):
        report = self.compile()
        self.assertTrue(report['ok'], report)
        lib = ctypes.CDLL(str(self.output))
        fn = lib.hia_byte_trace
        fn.argtypes = []
        fn.restype = ctypes.c_uint64
        self.assertEqual(fn(), report['expected_hash_u64'])
        self.assertGreater(report['artifact_bytes'], 1000)
        self.assertFalse(report['claims']['source_to_ir_refinement_proved'])

    def test_both_branch_outcomes_execute(self):
        for cond in (True, False):
            out = Path(self.dir.name) / f'oracle-{cond}.so'
            graph, checked = fixture(borrow=True)
            r = compile_native_byte_trace(graph, checked, 'f', inputs={'p0': cond},
                                          actions=({'kind':'alloc','bytes':5}, {'kind':'read','index':0}),
                                          output=out)
            dll = ctypes.CDLL(str(out))
            dll.hia_byte_trace.restype = ctypes.c_uint64
            self.assertEqual(dll.hia_byte_trace(), r['expected_hash_u64'])

    def test_real_mutable_byte_store_then_load_and_wrong_code_control(self):
        graph, _ = fixture(borrow=True)
        from hepta.resource_ir import verify_resource_ir
        ops = graph['functions'][0]['blocks'][0]['ops']
        ops[1]['mode'] = 'mut'
        ops[2]['mode'] = 'write'
        ops.insert(3, {'op': 'use', 'loan': 'loan0', 'mode': 'read'})
        checked = verify_resource_ir(graph)
        self.assertTrue(checked['ok'], checked)
        actions = ({'kind':'alloc','bytes':16}, {'kind':'write','index':5,'value':77},
                   {'kind':'read','index':5})
        report = compile_native_byte_trace(graph, checked, 'f', inputs={'p0':True},
                                           actions=actions, output=self.output)
        lib = ctypes.CDLL(str(self.output))
        lib.hia_byte_trace.restype = ctypes.c_uint64
        self.assertEqual(lib.hia_byte_trace(), report['expected_hash_u64'])
        witness = replay_byte_memory_path(graph, checked, 'f', inputs={'p0':True}, actions=actions)
        ir, expected = _render_native_byte_trace(witness)
        self.assertEqual(expected, report['expected_hash_u64'])
        self.assertIn('store volatile i8 77', ir)
        self.assertIn('load volatile i8', ir)
        corrupted = ir.replace('store volatile i8 77', 'store volatile i8 76')
        self.assertNotEqual(ir, corrupted)
        bad = Path(self.dir.name) / 'wrong.so'
        build = subprocess.run(['clang','-shared','-fPIC','-x','ir','-O0','-o',str(bad),'-'],
                               input=corrupted.encode(),capture_output=True,timeout=30)
        self.assertEqual(build.returncode, 0, build.stderr)
        # A wrong implementation must trip its compiled read-value guard.
        code = subprocess.run([sys.executable, '-c',
                               'import ctypes,sys; p=ctypes.CDLL(sys.argv[1]);p.hia_byte_trace.restype=ctypes.c_uint64;p.hia_byte_trace()',
                               str(bad)], capture_output=True, timeout=10)
        self.assertNotEqual(code.returncode, 0, 'corrupted store bypassed native guard')

    def test_wrong_or_oversized_script_rejects_without_publication(self):
        graph, checked = fixture(borrow=True)
        for actions in (({'kind':'alloc','bytes':4097}, {'kind':'read','index':0}),
                        ({'kind':'alloc','bytes':4}, {'kind':'read','index':True}),
                        ({'kind':'alloc','bytes':4}, {'kind':'write','index':1,'value':3})):
            with self.subTest(actions=actions):
                with self.assertRaises(ValueError):
                    compile_native_byte_trace(graph, checked, 'f', inputs={'p0':True},
                                              actions=actions, output=self.output)
                self.assertFalse(self.output.exists())

    def test_existing_output_refused_without_overwriting(self):
        self.output.write_bytes(b'keep')
        with self.assertRaisesRegex(HIANativeByteProbeRejected, 'E_HIA_NATIVE_BYTE'):
            self.compile()
        self.assertEqual(self.output.read_bytes(), b'keep')

    def test_llvm_render_rejects_forged_proof_and_memory_token(self):
        graph, checked = fixture(borrow=True)
        source = replay_byte_memory_path(graph, checked, 'f', inputs={'p0':True},
                                         actions=({'kind':'alloc','bytes':8}, {'kind':'read','index':0}))
        altered = dict(source)
        altered['claims'] = dict(source['claims'], pointer_provenance_proved=1)
        with self.assertRaisesRegex(HIANativeByteProbeRejected, 'E_HIA_NATIVE_BYTE'):
            _render_native_byte_trace(altered)
        altered = dict(source)
        altered['memory_observations'] = [dict(ev) for ev in source['memory_observations']]
        altered['memory_observations'][0]['memory_token'] = 0
        # Adversary can rehash a forged witness; typed effects still reject.
        payload = {k: v for k, v in altered.items() if k != 'trace_sha256'}
        altered['trace_sha256'] = sha256(json.dumps(payload, sort_keys=True,
                                     separators=(',', ':'), allow_nan=False).encode()).hexdigest()
        with self.assertRaisesRegex(HIANativeByteProbeRejected, 'memory token'):
            _render_native_byte_trace(altered)

if __name__ == '__main__':
    unittest.main()
