"""Real Python HIA verifier vs Rust interprocedural resource shadow."""
import json
from pathlib import Path
import shutil
import subprocess
import unittest

from hepta.hia_program import HIAProgramRejected, verify_program
from tests.test_hia_program import f, b, c, i, m, ret

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "rust" / "hia-core-shadow" / "Cargo.toml"

def call_owner():
    maker = f("maker", [("size", "usize")], ["buffer","bool"], ["alloc"], [
        b("maker_entry", [("size", "usize")], [
            i("buffer.try_new", ["size"], [("made", "buffer"),("ok", "bool")])
        ], ret("made","ok"))])
    use = f("use", [("n","usize")], ["usize","bool"], ["alloc"], [
        b("entry", [("n","usize")], [
            i("call", ["n"], [("owner", "buffer"),("succeeded","bool")], function="maker"),
            i("buffer.len", ["owner"], [("length", "usize")]),
            i("owner.drop", ["owner"])
        ], ret("length","succeeded"))])
    return m(maker, use)

def borrowed_call():
    reader = f("reader", [("view", "readbuf")], ["u8"], ["read","trap"], [
        b("read_entry", [("view", "readbuf")], [
            c("zero", "usize", 0),
            i("buffer.load", ["view", "zero"], [("byte", "u8")])
        ], ret("byte"))])
    outer = f("outer", [], ["u8"], ["alloc","read","trap"], [
        b("outer_entry", [], [
            c("size","usize",1), i("buffer.new",["size"],[("owner","buffer")]),
            i("borrow.mut",["owner"],[("parent","mutbuf")]),
            i("borrow.read",["parent"],[("child","readbuf")]),
            i("call",["child"],[("first","u8")],function="reader"),
            i("loan.end",["child"]),
            i("call",["parent"],[("second","u8")],function="reader"),
            i("loan.end",["parent"]),i("owner.drop",["owner"])
        ],ret("second"))])
    return m(reader, outer)

@unittest.skipUnless(shutil.which("cargo"), "Cargo unavailable; NOT Rust-qualified")
class RustOwnerCallComparison(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        p = subprocess.run(["cargo","build","--manifest-path",str(MANIFEST)],
                           cwd=ROOT, capture_output=True, text=True, timeout=240)
        if p.returncode:
            raise AssertionError("Rust build failed:\n"+p.stderr[-6000:])

    def rust(self, program):
        raw = program if isinstance(program,bytes) else json.dumps(program).encode()
        return subprocess.run(["cargo","run","--offline","--quiet",
                               "--manifest-path",str(MANIFEST),"--","--owned-shadow"],
                              cwd=ROOT,input=raw,capture_output=True,timeout=60)

    def test_genuine_internal_owner_and_readonly_borrow_calls(self):
        for factory in (call_owner, borrowed_call):
            with self.subTest(factory=factory.__name__):
                official = verify_program(factory())
                result = self.rust(official.canonical_bytes)
                self.assertEqual(result.returncode, 0,
                                 result.stderr.decode(errors="replace"))
                shadow = json.loads(result.stdout)
                self.assertEqual(shadow["program_sha256"], official.sha256)
                self.assertIs(shadow["claims"]["interprocedural_resource_calls_checked"], True)
                self.assertIs(shadow["claims"]["recursion_or_stack_bounds_proved"], False)
                self.assertIs(shadow["claims"]["rust_is_production_admission_authority"], False)

    def test_borrowed_call_exclusive_alias_is_refused(self):
        double = f("double", [("left","mutbuf"),("right","mutbuf")],
                   [], [], [b("double_entry", [("left","mutbuf"),
                                               ("right","mutbuf")], [], ret())])
        from tests.test_hia_program import resource_program
        p = resource_program()
        p["functions"].append(double)
        p["functions"][0]["blocks"][0]["ops"].insert(
            2, i("call", ["writer","writer"], function="double"))
        with self.assertRaises(HIAProgramRejected):
            verify_program(p)
        self.assertNotEqual(self.rust(p).returncode, 0)

    def test_double_consumption_and_effect_claims_are_rejected(self):
        invalid = []
        p = call_owner()
        p["functions"][1]["blocks"][0]["ops"].append(
            i("owner.drop",["owner"]))
        invalid.append(p)
        p = call_owner()
        p["functions"][1]["effects"] = []
        invalid.append(p)
        p = call_owner()
        p["functions"][1]["blocks"][0]["ops"][0]["attrs"]["function"] = "unknown"
        invalid.append(p)
        for bad in invalid:
            with self.assertRaises(HIAProgramRejected):
                verify_program(bad)
            self.assertNotEqual(self.rust(bad).returncode, 0)

if __name__ == "__main__":
    unittest.main()
