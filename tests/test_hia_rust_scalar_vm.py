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
from tests.test_hia_program import f, b, i, m, ret

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "rust" / "hia-core-shadow" / "Cargo.toml"


def arithmetic(op, typ="i64", effects=("trap",)):
    return m(f("calc", [("a", typ), ("b", typ)], [typ], list(effects), [
        b("entry", [("a", typ), ("b", typ)], [i(op, ["a", "b"], [("result", typ)])],
          ret("result"))]))


@unittest.skipUnless(shutil.which("cargo"), "Cargo missing: NO Rust/VM qualification")
class RustScalarVmParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        result = subprocess.run(["cargo", "build", "--manifest-path", str(MANIFEST)],
                                cwd=ROOT, capture_output=True, text=True, timeout=240)
        if result.returncode:
            raise AssertionError("Rust executable build failed:\n" + result.stderr[-6000:])

    def rust(self, program, function, arguments):
        raw = verify_program(program).canonical_bytes
        result = subprocess.run([
            "cargo", "run", "--quiet", "--offline", "--manifest-path", str(MANIFEST),
            "--", "--scalar-run", function, json.dumps(arguments, separators=(",", ":"))
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
