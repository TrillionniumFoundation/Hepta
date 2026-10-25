"""SSA join tests: exactly one local, one if/else assignment and return."""
from __future__ import annotations

import ctypes
from hashlib import sha256
import json
from pathlib import Path
import random
import shutil
import subprocess
import tempfile
import unittest

from hepta.llvm_scalar_backend import LLVMScalarRejected, emit_scalar_llvm, compile_scalar_llvm

_I32 = {"type": "i32", "args": [], "length": None}
_BOOL = {"type": "bool", "args": [], "length": None}


def expr(op, value, *operands, typ=None):
    return {"node": "expr", "operation": op, "value": value, "operands": list(operands),
            "result_type": typ or _I32, "type_args": [], "span": {}}


def statement(op, **fields):
    return {"node": "stmt", "operation": op, "fields": fields, "span": {}}


def build_hsir():
    a, b = expr('name', 'a'), expr('name', 'b')
    result = expr('name', 'result')
    condition = expr('binary', '<', a, b, typ=_BOOL)
    increment = expr('binary', '+', a, expr('int', 1))
    decrement = expr('binary', '-', b, expr('int', 1))
    body = [
        statement('let', name='result', type=_I32, mutable=True, expr=a),
        statement('if', condition=condition,
                  then=[statement('assign', target=result, expr=increment)],
                  **{'else': [statement('assign', target=result, expr=decrement)]}),
        statement('return', expr=result),
    ]
    function = {
        'name': 'choose', 'direction': 'export', 'abi': 'C',
        'return_type': _I32, 'type_parameters': [],
        'param_types': [{'name': name, 'type': _I32, 'ownership': 'value'} for name in ('a', 'b')],
        'declared_effects': ['panic'], 'inferred_transitive_effects': ['panic'],
        'resource_contract': {'heap_allocations': 0, 'may_block': False,
                              'may_suspend': False, 'may_spawn': False},
        'body': body,
    }
    obj = {'schema': 'hepta.hsir.v0', 'status': 'checked_frontend_snapshot_not_proved',
           'structs': [], 'enums': [], 'imports': [], 'external_assumptions': [],
           'functions': [function]}
    return seal(obj)


def seal(obj):
    value = {k: v for k, v in obj.items() if k != 'sha256'}
    value['sha256'] = sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=False).encode()).hexdigest()
    return value


class LLVMScalarPhiTests(unittest.TestCase):
    def test_exact_ssa_phi_uses_checked_continuation_predecessors(self):
        output = emit_scalar_llvm(build_hsir())
        self.assertIn('= phi i32', output.text)
        self.assertIn('icmp slt i32', output.text)
        self.assertRegex(output.text, r'phi i32 \[ %t\d+, %ok_\d+ \], \[ %t\d+, %ok_\d+ \]')
        self.assertIn('call void @abort()', output.text)
        self.assertNotIn('alloca', output.text)
        self.assertEqual(output, emit_scalar_llvm(build_hsir()))

    @unittest.skipUnless(shutil.which('clang') and shutil.which('gcc'), 'Clang/GCC required')
    def test_phi_executes_identically_to_independent_c_on_defined_inputs(self):
        output = emit_scalar_llvm(build_hsir())
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td)
            report = compile_scalar_llvm(output, output=folder / 'compiled.so')
            self.assertFalse(report['claims']['backend_semantics_proved'])
            source = folder / 'reference.c'
            source.write_text('int choose(int a,int b){int result=a; if(a<b)result=a+1;else result=b-1; return result;}')
            subprocess.run(['gcc', '-std=c11', '-O2', '-fPIC', '-shared',
                            str(source), '-o', str(folder / 'reference.so')],
                           check=True, capture_output=True, timeout=20)
            llvm = ctypes.CDLL(str(folder / 'compiled.so')).choose
            c = ctypes.CDLL(str(folder / 'reference.so')).choose
            for fn in (llvm, c):
                fn.argtypes = [ctypes.c_int32, ctypes.c_int32]
                fn.restype = ctypes.c_int32
            rng = random.Random(6252026)
            inputs = [(-2**31 + 1, 2**31 - 2), (-17, -9), (0, 0), (3, -1)]
            inputs += [(rng.randint(-25000, 25000), rng.randint(-25000, 25000))
                       for _ in range(800)]
            for a, b in inputs:
                with self.subTest(a=a, b=b):
                    self.assertEqual(llvm(a, b), c(a, b))
                    self.assertEqual(llvm(a, b), a + 1 if a < b else b - 1)

    def test_missing_definite_assignment_rejected(self):
        def bad(mutator, expected='E_LLVM_PHI'):
            snapshot = build_hsir()
            mutator(snapshot['functions'][0]['body'])
            with self.assertRaisesRegex(LLVMScalarRejected, expected):
                emit_scalar_llvm(seal(snapshot))
        bad(lambda stmts: stmts[1]['fields'].__setitem__('else', []))
        bad(lambda stmts: stmts[0]['fields'].__setitem__('mutable', False))
        bad(lambda stmts: stmts[0]['fields'].__setitem__('name', 'a'))
        bad(lambda stmts: stmts[1]['fields']['then'][0]['fields']['target'].__setitem__('value', 'a'))
        bad(lambda stmts: stmts[1]['fields']['then'][0].__setitem__('operation', 'return'))
        bad(lambda stmts: stmts[0]['fields'].__setitem__('type', _BOOL))

    def test_panic_effect_cannot_be_omitted_in_phi_arm(self):
        for field in ('declared_effects', 'inferred_transitive_effects'):
            snapshot = build_hsir()
            snapshot['functions'][0][field] = []
            with self.subTest(effect_field=field):
                with self.assertRaisesRegex(LLVMScalarRejected, 'E_LLVM_EFFECT'):
                    emit_scalar_llvm(seal(snapshot))

    def test_actual_hepta_frontend_integration_when_available(self):
        try:
            from hepta.parser import parse
            from hepta.checker import check
            from hepta.hsir import lower_checked_program
        except ModuleNotFoundError:
            self.skipTest('Hepta original compiler frontend unavailable in subset checkout')
        source = '''module select;
export "C" fn choose(a: i32, b: i32) -> i32 effects { panic }
resources { heap_allocations = 0; may_block = false; may_suspend = false; may_spawn = false; }
{
    let mut result: i32 = a;
    if a < b { result = a + 1; } else { result = b - 1; }
    return result;
}
'''
        program = parse(source)
        checked = check(program)
        self.assertTrue(checked.ok, checked.diagnostics)
        code = emit_scalar_llvm(lower_checked_program(program, checked))
        self.assertIn('phi i32', code.text)


if __name__ == '__main__':
    unittest.main()
