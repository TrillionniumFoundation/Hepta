"""Real LLVM cross-target i32 object compilation: object qualification only."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.llvm_scalar_backend import (
    ScalarIR, LLVMScalarRejected, compile_scalar_object, emit_scalar_llvm,
    _matches_object_target, _SCALAR_OBJECT_TARGETS,
)


def _valid_ir():
    i32 = {'type': 'i32', 'args': [], 'length': None}
    name = lambda x: {'node': 'expr', 'operation': 'name', 'value': x,
                      'result_type': i32, 'operands': [], 'type_args': [], 'span': {}}
    expression = {'node': 'expr', 'operation': 'binary', 'value': '+',
                  'result_type': i32, 'operands': [name('a'), name('b')],
                  'type_args': [], 'span': {}}
    function = {
        'name': 'checked_add', 'direction': 'export', 'abi': 'C',
        'return_type': i32, 'type_parameters': [],
        'param_types': [{'name': x, 'type': i32, 'ownership': 'value'} for x in ('a', 'b')],
        'declared_effects': ['panic'], 'inferred_transitive_effects': ['panic'],
        'resource_contract': {'heap_allocations': 0, 'may_block': False,
                              'may_suspend': False, 'may_spawn': False},
        'body': [{'node': 'stmt', 'operation': 'return',
                  'fields': {'expr': expression}, 'span': {}}],
    }
    snapshot = {'schema': 'hepta.hsir.v0', 'status': 'checked_frontend_snapshot_not_proved',
                'functions': [function], 'structs': [], 'enums': [],
                'imports': [], 'external_assumptions': []}
    snapshot['sha256'] = sha256(json.dumps(snapshot, sort_keys=True,
                                            separators=(',', ':'),
                                            ensure_ascii=False).encode()).hexdigest()
    return emit_scalar_llvm(snapshot)


class LLVMScalarTargetTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('clang'), 'Clang required for actual target object build')
    def test_three_target_objects_compile_with_real_llvm(self):
        ir = _valid_ir()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for target in _SCALAR_OBJECT_TARGETS:
                with self.subTest(target=target):
                    object_file = root / (target + '.o')
                    result = compile_scalar_object(ir, target=target, output=object_file)
                    self.assertEqual(result['target'], target)
                    self.assertEqual(result['status'], 'cross_object_only_unqualified')
                    self.assertEqual(result['functions'], ['checked_add'])
                    self.assertGreater(object_file.stat().st_size, 0)
                    self.assertTrue(_matches_object_target(object_file.read_bytes(), target))
                    self.assertEqual(result['artifact_sha256'], sha256(object_file.read_bytes()).hexdigest())
                    self.assertFalse(result['claims']['target_execution_verified'])
                    self.assertFalse(result['claims']['foreign_c_abi_verified'])
                    self.assertFalse(result['claims']['whole_p6_gate_closed'])

    def test_bad_target_or_ir_identity_fail_before_compiler(self):
        ir = _valid_ir()
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'bad.o'
            with self.assertRaisesRegex(LLVMScalarRejected, 'E_LLVM_TARGET'):
                compile_scalar_object(ir, target='nonexistent-target', output=output)
            with self.assertRaisesRegex(LLVMScalarRejected, 'E_LLVM_IR_IDENTITY'):
                compile_scalar_object(ScalarIR(ir.text, ir.sha256, ('bogus',)),
                                      target='aarch64-unknown-linux-gnu', output=output)
            self.assertFalse(output.exists())

    @unittest.skipUnless(shutil.which('clang'), 'Clang required for actual target object build')
    def test_object_output_is_atomic_no_overwrite(self):
        ir = _valid_ir()
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / 'target.o'
            dest.write_bytes(b'preexisting')
            with self.assertRaisesRegex(LLVMScalarRejected, 'E_LLVM_OUTPUT'):
                compile_scalar_object(ir, target='x86_64-unknown-linux-gnu', output=dest)
            self.assertEqual(dest.read_bytes(), b'preexisting')

    def test_wrong_object_machine_rejected(self):
        x86_elf = bytearray(20)
        x86_elf[:6] = b'\x7fELF\x02\x01'
        x86_elf[18:20] = (62).to_bytes(2, 'little')
        self.assertTrue(_matches_object_target(x86_elf, 'x86_64-unknown-linux-gnu'))
        self.assertFalse(_matches_object_target(x86_elf, 'aarch64-unknown-linux-gnu'))
        self.assertFalse(_matches_object_target(x86_elf, 'x86_64-pc-windows-msvc'))
        self.assertFalse(_matches_object_target(b'garbage', 'x86_64-unknown-linux-gnu'))


if __name__ == '__main__':
    unittest.main()
