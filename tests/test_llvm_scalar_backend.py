"""Executable independent LLVM IR experiments: checked i32, fail-closed."""
from __future__ import annotations

import ctypes
from hashlib import sha256
import json
from pathlib import Path
import random
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest

from hepta.llvm_scalar_backend import LLVMScalarRejected, emit_scalar_llvm, compile_scalar_llvm


def _expr(kind, value, *operands):
    return {"node": "expr", "operation": kind, "value": value,
            "result_type": {"type": "i32", "args": [], "length": None},
            "operands": list(operands), "type_args": [], "span": {}}


def _snapshot():
    functions = []
    for name, op in (("checked_add", "+"), ("checked_sub", "-"),
                     ("checked_mul", "*"), ("wrapped_add", "wrapping_add")):
        params = [{"name": k, "type": {"type": "i32", "args": [], "length": None},
                   "ownership": "value"} for k in ("a", "b")]
        body = [{"node": "stmt", "operation": "return", "fields": {
                 "expr": _expr("call" if op.startswith("wrapping") else "binary", op,
                               _expr("name", "a"), _expr("name", "b"))}}]
        functions.append({"name": name, "direction": "export", "abi": "C",
                          "return_type": {"type": "i32", "args": [], "length": None},
                          "param_types": params, "type_parameters": [],
                          "body": body, "declared_effects": ["panic"] if not op.startswith("wrapping") else [],
                          "inferred_transitive_effects": ["panic"] if not op.startswith("wrapping") else [],
                          "resource_contract": {"heap_allocations": 0,
                                                "may_block": False, "may_suspend": False,
                                                "may_spawn": False}})
    root = {"schema": "hepta.hsir.v0", "status": "checked_frontend_snapshot_not_proved",
            "structs": [], "enums": [], "imports": [], "external_assumptions": [],
            "functions": functions}
    return _seal(root)


def _seal(data):
    body = {k: v for k, v in data.items() if k != "sha256"}
    body["sha256"] = sha256(json.dumps(body, sort_keys=True, separators=(",", ":"),
                                      ensure_ascii=False).encode()).hexdigest()
    return body


class LLVMScalarBackendTests(unittest.TestCase):
    def test_scalar_llvm_ir_is_reproducible(self):
        a = emit_scalar_llvm(_snapshot())
        b = emit_scalar_llvm(_snapshot())
        self.assertEqual(a, b)
        self.assertIn("@llvm.sadd.with.overflow.i32", a.text)
        self.assertIn("call void @abort()", a.text)
        self.assertIn("define i32 @wrapped_add", a.text)
        self.assertNotIn("rustc", a.text)

    def test_forged_or_unsafe_profiles_fail_closed(self):
        mutated = _snapshot()
        mutated["functions"][0]["declared_effects"].append("unsafe")
        with self.assertRaisesRegex(LLVMScalarRejected, "SNAPSHOT"):
            emit_scalar_llvm(mutated)
        with self.assertRaisesRegex(LLVMScalarRejected, "E_LLVM_EFFECT"):
            emit_scalar_llvm(_seal(mutated))
        mutated = _snapshot()
        mutated["functions"][0]["param_types"][0]["ownership"] = "mut"
        with self.assertRaisesRegex(LLVMScalarRejected, "E_LLVM_TYPE"):
            emit_scalar_llvm(_seal(mutated))
        mutated = _snapshot()
        mutated["functions"][0]["body"][0]["operation"] = "unsafe"
        with self.assertRaisesRegex(LLVMScalarRejected, "E_LLVM_STMT"):
            emit_scalar_llvm(_seal(mutated))
        mutated = _snapshot()
        mutated["functions"][0]["body"][0]["fields"]["expr"] = _expr("int", 2**40)
        with self.assertRaisesRegex(LLVMScalarRejected, "E_LLVM_LITERAL"):
            emit_scalar_llvm(_seal(mutated))

    def test_host_if_else_cfg_against_independent_c(self):
        snap = _snapshot()
        fn = snap['functions'][3]
        fn['name'] = 'hepta_min2'
        condition = {'node': 'expr', 'operation': 'binary', 'value': '<',
                     'result_type': {'type': 'bool', 'args': [], 'length': None},
                     'operands': [_expr('name', 'a'), _expr('name', 'b')],
                     'type_args': [], 'span': {}}
        then_arm = [{'node': 'stmt', 'operation': 'return',
                     'fields': {'expr': _expr('name', 'a')}}]
        else_arm = [{'node': 'stmt', 'operation': 'return',
                     'fields': {'expr': _expr('name', 'b')}}]
        fn['body'] = [{'node': 'stmt', 'operation': 'if',
                       'fields': {'condition': condition, 'then': then_arm, 'else': else_arm}}]
        snap['functions'] = [fn]
        llvm = emit_scalar_llvm(_seal(snap))
        self.assertIn('icmp slt i32', llvm.text)
        self.assertIn('label %then_', llvm.text)
        self.assertIn('label %else_', llvm.text)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            if shutil.which('clang') and shutil.which('gcc'):
                compile_scalar_llvm(llvm, output=root / 'hepta.so')
                (root / 'reference.c').write_text('int hepta_min2(int a,int b){if(a<b)return a;else return b;}')
                subprocess.run(['gcc', '-std=c11', '-fPIC', '-O2', '-shared',
                                str(root / 'reference.c'), '-o', str(root / 'reference.so')],
                               check=True, capture_output=True, timeout=20)
                l = ctypes.CDLL(str(root / 'hepta.so')).hepta_min2
                r = ctypes.CDLL(str(root / 'reference.so')).hepta_min2
                for f in (l, r):
                    f.restype = ctypes.c_int32
                    f.argtypes = [ctypes.c_int32, ctypes.c_int32]
                rng = random.Random(52691)
                for a, b in [(-2**31, 2**31-1), (0, 0), (12, -5)] + [
                    (rng.randrange(-2**31, 2**31), rng.randrange(-2**31, 2**31))
                    for _ in range(100)]:
                    self.assertEqual(l(a, b), r(a, b), (a, b))
        snap['functions'][0]['body'][0]['fields']['else'] = []
        with self.assertRaisesRegex(LLVMScalarRejected, 'E_LLVM_STMT'):
            emit_scalar_llvm(_seal(snap))
        snap['functions'][0]['body'][0]['fields']['else'] = else_arm
        condition['value'] = '&&'
        with self.assertRaisesRegex(LLVMScalarRejected, 'E_LLVM_CONDITION'):
            emit_scalar_llvm(_seal(snap))

    def test_backend_rejects_modified_ir_before_invoking_compiler(self):
        from hepta.llvm_scalar_backend import ScalarIR
        legitimate = emit_scalar_llvm(_snapshot())
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "modified.so"
            invalid = ScalarIR(legitimate.text + "\n", legitimate.sha256,
                               legitimate.functions)
            with self.assertRaisesRegex(LLVMScalarRejected, "E_LLVM_IR_IDENTITY"):
                compile_scalar_llvm(invalid, output=path)
            self.assertFalse(path.exists())
            invalid = ScalarIR(legitimate.text, legitimate.sha256,
                               legitimate.functions, profile="unsupported")
            with self.assertRaisesRegex(LLVMScalarRejected, "E_LLVM_IR_IDENTITY"):
                compile_scalar_llvm(invalid, output=path)

    def test_checked_arithmetic_cannot_hide_panic_effect(self):
        for effect_field in ("declared_effects", "inferred_transitive_effects"):
            snapshot = _snapshot()
            snapshot["functions"][0][effect_field] = []
            with self.subTest(effect_field=effect_field):
                with self.assertRaisesRegex(LLVMScalarRejected, "E_LLVM_EFFECT"):
                    emit_scalar_llvm(_seal(snapshot))
        # The wrapping profile remains effect-free, while unary negation also
        # requires panic for MIN_INT, as does an ordinary checked subtraction.
        snapshot = _snapshot()
        snapshot["functions"] = [snapshot["functions"][3]]
        self.assertIn("define i32 @wrapped_add", emit_scalar_llvm(_seal(snapshot)).text)
        snapshot["functions"][0]["body"][0]["fields"]["expr"] = _expr(
            "unary", "-", _expr("name", "a"))
        with self.assertRaisesRegex(LLVMScalarRejected, "E_LLVM_EFFECT"):
            emit_scalar_llvm(_seal(snapshot))

    @unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("clang") and shutil.which("gcc"), "Linux, LLVM Clang and GCC required")
    def test_host_llvm_abi_matches_independent_c_for_defined_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = compile_scalar_llvm(emit_scalar_llvm(_snapshot()), output=root / "hepta_llvm.so")
            self.assertEqual(report["status"], "native_host_compiled_unqualified")
            self.assertFalse(report["claims"]["backend_semantics_proved"])
            self.assertFalse(report["claims"]["whole_p6_gate_closed"])
            native = root / "original.c"
            native.write_text("""int checked_add(int a,int b){return a+b;}
int checked_sub(int a,int b){return a-b;}
int checked_mul(int a,int b){return a*b;}
""")
            c_path = root / "original.so"
            subprocess.run(["gcc", "-std=c11", "-O2", "-fPIC", "-shared",
                            str(native), "-o", str(c_path)], check=True, capture_output=True, timeout=20)
            llvm = ctypes.CDLL(str(root / "hepta_llvm.so"))
            c = ctypes.CDLL(str(c_path))
            rng = random.Random(20261024)
            for name, op in (("checked_add", lambda a, b: a+b),
                             ("checked_sub", lambda a,b: a-b),
                             ("checked_mul", lambda a,b: a*b)):
                left, right = getattr(llvm, name), getattr(c, name)
                for fn in (left, right):
                    fn.argtypes = [ctypes.c_int32, ctypes.c_int32]
                    fn.restype = ctypes.c_int32
                for _ in range(100):
                    a, b = rng.randrange(-20000, 20001), rng.randrange(-20000, 20001)
                    expected = op(a,b)
                    if not -(2**31) <= expected < 2**31:
                        continue
                    with self.subTest(name=name, a=a, b=b):
                        self.assertEqual(left(a,b),right(a,b))
                        self.assertEqual(left(a,b),expected)
            wrap = llvm.wrapped_add
            wrap.argtypes = [ctypes.c_int32,ctypes.c_int32]
            wrap.restype = ctypes.c_int32
            self.assertEqual(wrap(2147483647,1),-(2**31))
            # Overflow must not produce LLVM poison/undefined behavior; it
            # takes the abort path in a separate process.
            script = """import ctypes,resource,sys
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
f=ctypes.CDLL(sys.argv[1]).checked_add
f.argtypes=[ctypes.c_int32,ctypes.c_int32]
f(2147483647,1)
"""
            child = subprocess.run([sys.executable, "-c", script, str(root / "hepta_llvm.so")],
                                   capture_output=True, timeout=10)
            self.assertEqual(child.returncode, -signal.SIGABRT)

    def test_cli_does_not_bypass_reference_native_gate(self):
        try:
            from hepta.cli import main
        except ImportError:
            self.skipTest("full Hepta CLI not mounted here")
        from contextlib import redirect_stdout
        from io import StringIO
        from types import SimpleNamespace
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "scalar.hepta"
            source.write_text("module scalar;", encoding="utf-8")
            output = Path(tmp) / "scalar.so"
            rejected = SimpleNamespace(report={"ok": False, "status": "rejected", "diagnostics": []})
            with patch("hepta.cli.analyze_project", return_value=rejected) as analyze, patch(
                "hepta.llvm_scalar_backend.compile_scalar_llvm",
                side_effect=AssertionError("LLVM must not run without rustc validation")
            ) as native:
                with redirect_stdout(StringIO()):
                    code = main(["build-llvm-scalar", str(source), "-o", str(output),
                                 "--rustc", "/nonexistent/rustc"])
            self.assertEqual(code, 1)
            self.assertFalse(output.exists())
            self.assertTrue(analyze.called)
            self.assertTrue(analyze.call_args.kwargs["native"])
            native.assert_not_called()

    def test_integration_with_actual_parser_checker_when_available(self):
        try:
            from hepta.parser import parse
            from hepta.checker import check
            from hepta.hsir import lower_checked_program
        except ImportError:
            self.skipTest("full Hepta bootstrap frontend not mounted here")
        src = '''module llvm_fixture;
export "C" fn add(a: i32, b: i32) -> i32 effects { panic } {
    return a + b;
}
'''
        program = parse(src)
        checked = check(program)
        self.assertTrue(checked.ok, [d.to_dict() for d in checked.diagnostics])
        ir = emit_scalar_llvm(lower_checked_program(program, checked))
        self.assertIn("define i32 @add", ir.text)


if __name__ == "__main__":
    unittest.main()
