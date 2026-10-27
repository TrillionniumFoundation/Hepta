"""Rust independent scalar interpreter parity against the canonical Python VM.

Requires a real cargo toolchain; missing cargo is a skip, never a passed proof.
The Python interpreter remains the production semantic authority.
"""
import json
from pathlib import Path
import shutil
import subprocess
import unittest

from hepta.hia_program import verify_program, HIAProgramRejected
from hepta.hia_program_runtime import execute_program, HIAProgramTrap, HIAProgramBudgetExceeded
from tests.test_hia_program import f, b, c, i, m, ret, jump, branch

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "rust" / "hia-core-shadow" / "Cargo.toml"


def arithmetic(op, typ="i64", effects=("trap",)):
    return m(f("calc", [("a", typ), ("b", typ)], [typ], list(effects), [
        b("entry", [("a", typ), ("b", typ)], [i(op, ["a", "b"], [("result", typ)])],
          ret("result"))]))



def phi_loop():
    return m(f("counter", [("n", "u32")], ["u32"], ["trap"], [
        b("entry", [("n", "u32")], [
            c("zero", "u32", 0), c("one", "u32", 1)
        ], jump("loop", "n", "zero", "one")),
        b("loop", [("remain", "u32"), ("total", "u32"), ("step", "u32")], [
            c("zero_loop", "u32", 0),
            i("compare.gt", ["remain", "zero_loop"], [("condition", "bool")])
        ], branch("condition", ("body", "remain", "total", "step"), ("done", "total"))),
        b("body", [("r", "u32"), ("acc", "u32"), ("s", "u32")], [
            i("int.sub.checked", ["r", "s"], [("remaining", "u32")]),
            i("int.add.checked", ["acc", "s"], [("updated", "u32")])
        ], jump("loop", "remaining", "updated", "s")),
        b("done", [("answer", "u32")], [], ret("answer"))
    ]))


def nested_calls():
    twice = f("twice", [("x", "u32")], ["u32"], ["trap"], [
        b("twice_entry", [("x", "u32")], [
            c("two", "u32", 2),
            i("int.mul.checked", ["x", "two"], [("doubled", "u32")])
        ], ret("doubled"))
    ])
    outer = f("outer", [("n", "u32")], ["u32"], ["trap"], [
        b("outer_entry", [("n", "u32")], [
            i("call", ["n"], [("first", "u32")], function="twice"),
            i("call", ["n"], [("second", "u32")], function="twice"),
            i("int.add.checked", ["first", "second"], [("total", "u32")])
        ], ret("total"))
    ])
    return m(twice, outer)


def recursive_call():
    return m(f("recur", [("n", "i32")], ["i32"], [], [
        b("entry", [("n", "i32")], [
            i("call", ["n"], [("v", "i32")], function="recur")
        ], ret("v"))
    ]))

@unittest.skipUnless(shutil.which("cargo"), "Cargo missing: NO Rust/VM qualification")
class RustScalarVmParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        result = subprocess.run(["cargo", "build", "--manifest-path", str(MANIFEST)],
                                cwd=ROOT, capture_output=True, text=True, timeout=240)
        if result.returncode:
            raise AssertionError("Rust executable build failed:\n" + result.stderr[-6000:])

    def rust(self, program, function, arguments, *, max_steps=100_000):
        raw = verify_program(program).canonical_bytes
        result = subprocess.run([
            "cargo", "run", "--quiet", "--offline", "--manifest-path", str(MANIFEST),
            "--", "--scalar-run", function, json.dumps(arguments, separators=(",", ":")),
            str(max_steps)
        ], input=raw, cwd=ROOT, capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 0,
                         result.stderr.decode(errors="replace"))
        return json.loads(result.stdout)

    def test_signed_divrem_and_wrap_and_overflow(self):
        cases = [
            ("int.div.checked", "i64", (-7, 3)),
            ("int.rem.checked", "i64", (-7, 3)),
            ("int.div.checked", "i64", (1, 0)),
            ("int.div.checked", "i64", (-2**63, -1)),
            ("int.shl.checked", "i64", (2**62, 2)),
            ("int.shr.checked", "i64", (-9, 2)),
            ("int.add.checked", "u64", (2**64 - 1, 1)),
            ("int.mul.wrap", "u64", (2**64 - 1, 2**64 - 1)),
        ]
        for op, typ, args in cases:
            with self.subTest(op=op, typ=typ, args=args):
                source = arithmetic(op, typ)
                rust = self.rust(source, "calc", list(args))
                try:
                    python = execute_program(source, "calc", list(args), max_call_depth=32)
                except HIAProgramTrap as exc:
                    python = exc.report
                self.assertEqual(rust["status"], python["status"])
                self.assertEqual(rust["steps"], python["steps"])
                if rust["status"] == "returned":
                    self.assertEqual(rust["values"], python["values"])
                else:
                    self.assertEqual(rust["error"]["code"], python["error"]["code"])

    def test_ssa_phi_loop_nested_calls_and_budget(self):
        cases = [
            (phi_loop(), "counter", [5], 100_000),
            (nested_calls(), "outer", [7], 100_000),
            (phi_loop(), "counter", [99], 5),
            (recursive_call(), "recur", [1], 100_000),
        ]
        for program, entry, args, max_steps in cases:
            with self.subTest(entry=entry, args=args, budget=max_steps):
                rust = self.rust(program, entry, args, max_steps=max_steps)
                try:
                    python = execute_program(program, entry, args,
                                             max_steps=max_steps, max_call_depth=32)
                except (HIAProgramTrap, HIAProgramBudgetExceeded) as exc:
                    python = exc.report
                self.assertEqual(rust["status"], python["status"])
                self.assertEqual(rust["steps"], python["steps"])
                if python["status"] == "returned":
                    self.assertEqual(rust["values"], python["values"])
                else:
                    self.assertEqual(rust["error"]["code"], python["error"]["code"])

    def test_failure_is_input_or_verifier_rejection_not_execution(self):
        source = arithmetic("int.add.checked", "u32")
        canonical = verify_program(source).canonical_bytes
        wrong = subprocess.run([
            "cargo", "run", "--quiet", "--offline", "--manifest-path", str(MANIFEST),
            "--", "--scalar-run", "calc", "[true,2]"
        ], input=canonical, cwd=ROOT, capture_output=True, timeout=60)
        self.assertNotEqual(wrong.returncode, 0)
        self.assertEqual(self.rust(source, "calc", [2, 3])["values"], [5])


if __name__ == "__main__":
    unittest.main()
