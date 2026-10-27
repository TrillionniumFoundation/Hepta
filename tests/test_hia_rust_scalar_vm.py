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


def depth_boundary():
    # Root is depth 0; n=32 succeeds at nested depth 32, n=33 refuses
    # before the next recursive call's entry tick. Block SSA names are
    # globally distinct even when reached through separate branch edges.
    return m(f("bounded", [("n", "u32")], ["u32"], ["trap"], [
        b("entry", [("n", "u32")], [
            c("zero", "u32", 0),
            i("compare.eq", ["n", "zero"], [("at_zero", "bool")]),
        ], branch("at_zero", ("complete", "n"), ("work", "n"))),
        b("complete", [("final", "u32")], [], ret("final")),
        b("work", [("remaining", "u32")], [
            c("one", "u32", 1),
            i("int.sub.checked", ["remaining", "one"], [("previous", "u32")]),
            i("call", ["previous"], [("result", "u32")], function="bounded"),
        ], ret("result")),
    ]))


def eager_cast_select():
    return m(f("choose", [("a", "i32"), ("b", "i32"), ("pick", "bool")],
               ["u8"], ["trap"], [
        b("entry", [("a", "i32"), ("b", "i32"), ("pick", "bool")], [
            i("int.cast", ["a"], [("checked", "u8")], mode="checked"),
            i("int.cast", ["b"], [("wrapped", "u8")], mode="wrap"),
            i("bool.not", ["pick"], [("opposite", "bool")]),
            i("bool.not", ["opposite"], [("chosen", "bool")]),
            i("select", ["chosen", "checked", "wrapped"], [("result", "u8")]),
        ], ret("result"))
    ]))


def boolean_composition():
    return m(f("check", [("left", "bool"), ("right", "bool")],
               ["bool"], [], [
        b("entry", [("left", "bool"), ("right", "bool")], [
            i("bool.and", ["left", "right"], [("both", "bool")]),
            i("bool.or", ["left", "right"], [("either", "bool")]),
            i("bool.not", ["both"], [("negated", "bool")]),
            i("compare.eq", ["negated", "either"], [("answer", "bool")])
        ], ret("answer"))
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
            # Signed MIN / -1 and MIN % -1 BOTH trap in the HIA ISA;
            # the i128 Rust implementation must not accept a remainder 0.
            ("int.rem.checked", "i64", (-2**63, -1)),
            ("int.rem.checked", "i32", (-2**31, -1)),
            ("int.rem.checked", "i16", (-2**15, -1)),
            ("int.rem.checked", "i8", (-2**7, -1)),
            ("int.div.checked", "i8", (-2**7, -1)),
            ("int.rem.checked", "i64", (-2**63, -2)),
            ("int.rem.checked", "u64", (2**64 - 1, 1)),
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

    def test_old_v6_canonical_core_rejects_explicit_exports(self):
        source = nested_calls()
        source["exports"] = ["outer"]
        # An independent Rust shadow must not be credited with parity for
        # a top-level field the canonical Python v6 Core does not recognize.
        with self.assertRaisesRegex(HIAProgramRejected, "E_HIA_FORMAT"):
            verify_program(source)

    def test_recursive_depth_boundary_and_budget_ticks_match_exactly(self):
        for n in (0, 1, 31, 32, 33):
            with self.subTest(n=n):
                source = depth_boundary()
                rust = self.rust(source, "bounded", [n])
                try:
                    python = execute_program(source, "bounded", [n],
                                             max_call_depth=32)
                except HIAProgramBudgetExceeded as exc:
                    python = exc.report
                self.assertEqual(rust["status"], python["status"])
                self.assertEqual(rust["steps"], python["steps"])
                if n <= 32:
                    self.assertEqual(rust["status"], "returned")
                    self.assertEqual(rust["values"], python["values"])
                else:
                    self.assertEqual(rust["status"], "budget_exceeded")
                    self.assertEqual(rust["error"]["code"], "calls")

        rust = self.rust(recursive_call(), "recur", [1], max_steps=100_000)
        try:
            execute_program(recursive_call(), "recur", [1],
                            max_steps=100_000, max_call_depth=32)
        except HIAProgramBudgetExceeded as exc:
            python = exc.report
        else:
            self.fail("canonical Python recursion must exceed depth budget")
        self.assertEqual(rust["status"], "budget_exceeded")
        self.assertEqual(rust["error"]["code"], "calls")
        self.assertEqual(rust["steps"], python["steps"])
        self.assertEqual(rust["steps"], 66)

    def test_select_casts_boolean_and_eager_traps(self):
        cases = [
            (eager_cast_select(), "choose", [12, -1, True]),
            (eager_cast_select(), "choose", [12, -1, False]),
            # Even the unselected side is evaluated when it is an earlier
            # SSA operation: a trapping checked cast cannot be skipped.
            (eager_cast_select(), "choose", [-1, 7, False]),
            (boolean_composition(), "check", [True, True]),
            (boolean_composition(), "check", [True, False]),
            (boolean_composition(), "check", [False, False]),
        ]
        for program, entry, args in cases:
            with self.subTest(entry=entry, args=args):
                rust = self.rust(program, entry, args)
                try:
                    python = execute_program(program, entry, args, max_call_depth=32)
                except HIAProgramTrap as exc:
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
